use crate::broker::state::{AgentState, BrokerState};
use crate::broker::DeliveryEngine;
use crate::db::repository::PendingMessage;
use crate::stanza::{self, Destination};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post, put, delete};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Shared application state passed to all route handlers.
pub struct AppState {
    pub broker: Arc<BrokerState>,
    pub delivery: Arc<DeliveryEngine>,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/projects/register", post(register_project))
        .route("/agents/register", post(register_agent))
        .route("/agents", get(list_agents))
        .route("/presence", put(update_presence))
        .route("/send", post(send_message))
        .route("/messages", get(get_messages))
        .route("/channels/{id}/subscribe", post(subscribe_channel))
        .route("/channels/{id}/unsubscribe", delete(unsubscribe_channel))
        .route("/health", get(health))
}

// --- Request/Response types ---

#[derive(Deserialize)]
pub struct RegisterProjectRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct RegisterProjectResponse {
    pub project_key: String,
}

#[derive(Deserialize)]
pub struct RegisterAgentRequest {
    pub name: String,
    pub project: String,
    pub project_key: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Serialize)]
pub struct RegisterAgentResponse {
    pub session_id: String,
}

#[derive(Deserialize)]
pub struct AuthenticatedRequest {
    pub name: String,
    pub project: String,
    pub project_key: String,
    #[serde(default)]
    pub state: AgentState,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub message_id: String,
}

#[derive(Deserialize)]
pub struct AgentQuery {
    pub project: Option<String>,
}

#[derive(Deserialize)]
pub struct MessageQuery {
    pub name: String,
    pub project: String,
    pub project_key: String,
}

// --- Helpers ---

fn verify_key(state: &AppState, project: &str, key: &str) -> Result<(), (StatusCode, String)> {
    if !state.broker.repo.verify_project_key(project, key) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid project key".to_string()));
    }
    Ok(())
}

fn extract_auth(headers: &HeaderMap) -> Result<(&str, &str), (StatusCode, String)> {
    let project = headers
        .get("x-project")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "Missing X-Project header".to_string()))?;
    let key = headers
        .get("x-project-key")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "Missing X-Project-Key header".to_string()))?;
    Ok((project, key))
}

// --- Handlers ---

async fn health() -> &'static str {
    "ok"
}

async fn register_project(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterProjectRequest>,
) -> Result<Json<RegisterProjectResponse>, (StatusCode, String)> {
    let project_key = uuid::Uuid::new_v4().to_string();
    state.broker.repo.register_project(&req.name, &project_key)
        .map_err(|e| (StatusCode::CONFLICT, e))?;

    tracing::info!("Project registered: {}", req.name);
    Ok(Json(RegisterProjectResponse { project_key }))
}

async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, String)> {
    verify_key(&state, &req.project, &req.project_key)?;

    state.broker.repo.register_agent(&req.name, &req.project, &req.role)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let _rx = state.broker.connect(&req.name, &req.project, &session_id).await;

    tracing::info!("Agent registered: {}.{}", req.name, req.project);
    Ok(Json(RegisterAgentResponse { session_id }))
}

async fn update_presence(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthenticatedRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_key(&state, &req.project, &req.project_key)?;
    state.broker.set_state(&req.name, &req.project, req.state).await;
    Ok(StatusCode::OK)
}

async fn list_agents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AgentQuery>,
) -> Json<Vec<crate::broker::state::AgentInfo>> {
    let agents = state.broker.list_agents(query.project.as_deref()).await;
    Json(agents)
}

/// Accept raw stanza XML. Auth via X-Project / X-Project-Key headers.
async fn send_message(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<SendResponse>, (StatusCode, String)> {
    let (project, key) = extract_auth(&headers)?;
    verify_key(&state, project, key)?;

    let parsed = stanza::parse(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid stanza: {e}")))?;

    match parsed {
        stanza::Stanza::Message(msg) => {
            if !state.broker.repo.agent_exists(&msg.from, project) {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("Agent '{}' not registered in project '{}'", msg.from, project),
                ));
            }

            let id = uuid::Uuid::new_v4().to_string();
            let (to_agent, to_channel) = match stanza::resolve_destination(&msg.to) {
                Destination::Agent(a) => (Some(a), None),
                Destination::Channel(c) => (None, Some(c)),
            };

            state
                .delivery
                .deliver(
                    &id,
                    &msg.from,
                    project,
                    to_agent.as_deref(),
                    to_channel.as_deref(),
                    &msg.raw,
                    None,
                )
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

            Ok(Json(SendResponse { message_id: id }))
        }
        stanza::Stanza::Presence(p) => {
            let agent_state = match p.status {
                stanza::PresenceStatus::Available => AgentState::Available,
                stanza::PresenceStatus::Busy => AgentState::Busy,
                stanza::PresenceStatus::Offline => AgentState::Offline,
            };
            state.broker.set_state(&p.from, project, agent_state).await;
            Ok(Json(SendResponse { message_id: String::new() }))
        }
    }
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MessageQuery>,
) -> Result<Json<Vec<PendingMessage>>, (StatusCode, String)> {
    verify_key(&state, &query.project, &query.project_key)?;
    let messages = state.delivery.drain_pending(&query.name, &query.project);
    Ok(Json(messages))
}

async fn subscribe_channel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    Json(req): Json<AuthenticatedRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_key(&state, &req.project, &req.project_key)?;
    state.broker.repo.ensure_channel(&channel_id, &req.project);
    state.broker.repo.subscribe(&req.name, &req.project, &channel_id);
    Ok(StatusCode::OK)
}

async fn unsubscribe_channel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    Json(req): Json<AuthenticatedRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_key(&state, &req.project, &req.project_key)?;
    state.broker.repo.unsubscribe(&req.name, &req.project, &channel_id);
    Ok(StatusCode::OK)
}

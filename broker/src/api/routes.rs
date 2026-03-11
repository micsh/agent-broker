use crate::api::auth::ProjectAuth;
use crate::broker::state::{AgentState, BrokerState};
use crate::broker::{DeliveryEngine, dispatch_stanza, DispatchResult, DispatchError};
use crate::db::repository::PendingMessage;
use crate::stanza;
use axum::extract::{Query, State};
use axum::http::StatusCode;
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
        .route("/messages/peek", get(peek_messages))
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

/// Presence update payload -- credentials carried by ProjectAuth extractor.
#[derive(Deserialize)]
pub struct PresenceRequest {
    pub name: String,
    #[serde(default)]
    pub state: AgentState,
}

/// Channel subscribe/unsubscribe payload -- credentials carried by ProjectAuth extractor.
#[derive(Deserialize)]
pub struct ChannelRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub message_id: String,
}

#[derive(Deserialize)]
pub struct AgentQuery {
    pub project: Option<String>,
}

/// Message retrieval query -- project is supplied via X-Project header (ProjectAuth extractor).
#[derive(Deserialize)]
pub struct MessageQuery {
    pub name: String,
}

#[derive(Serialize)]
pub struct PeekSender {
    pub from: String,
    pub at: String,
}

#[derive(Serialize)]
pub struct PeekResponse {
    pub count: usize,
    pub senders: Vec<PeekSender>,
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
    state.broker.register_project(&req.name, &project_key)
        .map_err(|e| (StatusCode::CONFLICT, e))?;

    tracing::info!("Project registered: {}", req.name);
    Ok(Json(RegisterProjectResponse { project_key }))
}

/// POST /agents/register -- body auth (first-contact route; caller has no session context yet).
async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, String)> {
    if !state.broker.verify_project_key(&req.project, &req.project_key) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid project key".to_string()));
    }

    if !state.broker.project_exists(&req.project) {
        return Err((StatusCode::NOT_FOUND, format!("Project '{}' not found", req.project)));
    }

    state.broker.register_agent(&req.name, &req.project, &req.role)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // NOTE: this is a correlation ID only -- live sessions are created exclusively on WS handshake.
    let session_id = uuid::Uuid::new_v4().to_string();

    tracing::info!("Agent registered: {}.{}", req.name, req.project);
    Ok(Json(RegisterAgentResponse { session_id }))
}

async fn list_agents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AgentQuery>,
) -> Json<Vec<crate::broker::state::AgentInfo>> {
    let agents = state.broker.list_agents(query.project.as_deref()).await;
    Json(agents)
}

/// Accept raw stanza XML. Auth via ProjectAuth extractor (X-Project + X-Project-Key headers).
async fn send_message(
    State(state): State<Arc<AppState>>,
    ProjectAuth { project }: ProjectAuth,
    body: String,
) -> Result<Json<SendResponse>, (StatusCode, String)> {
    let parsed = stanza::parse(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid stanza: {e}")))?;

    // Validate sender exists before dispatch
    if let stanza::Stanza::Message(ref msg) = parsed {
        if !state.broker.agent_exists(&msg.from, &project) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Agent '{}' not registered in project '{}'", msg.from, project),
            ));
        }
    }

    match dispatch_stanza(parsed, &project, &state.broker, &state.delivery, true).await {
        Ok(DispatchResult::MessageSent(id)) => Ok(Json(SendResponse { message_id: id })),
        Ok(DispatchResult::PresenceUpdated) => Ok(Json(SendResponse { message_id: String::new() })),
        Err(DispatchError::TargetNotFound { agent, project }) => Err((
            StatusCode::BAD_REQUEST,
            format!("Target agent '{}' not found in project '{}'", agent, project),
        )),
        Err(DispatchError::DeliveryFailed(e)) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

async fn update_presence(
    State(state): State<Arc<AppState>>,
    ProjectAuth { project }: ProjectAuth,
    Json(req): Json<PresenceRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.set_state(&req.name, &project, req.state).await;
    Ok(StatusCode::OK)
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    ProjectAuth { project }: ProjectAuth,
    Query(query): Query<MessageQuery>,
) -> Result<Json<Vec<PendingMessage>>, (StatusCode, String)> {
    let messages = state.delivery.drain_pending(&query.name, &project);
    Ok(Json(messages))
}

async fn peek_messages(
    State(state): State<Arc<AppState>>,
    ProjectAuth { project }: ProjectAuth,
    Query(query): Query<MessageQuery>,
) -> Result<Json<PeekResponse>, (StatusCode, String)> {
    let pending = state.broker.peek_pending(&query.name, &project);
    let senders: Vec<PeekSender> = pending
        .iter()
        .map(|(agent, proj, at)| PeekSender {
            from: format!("{}.{}", agent, proj),
            at: at.clone(),
        })
        .collect();
    Ok(Json(PeekResponse {
        count: senders.len(),
        senders,
    }))
}

async fn subscribe_channel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    ProjectAuth { project }: ProjectAuth,
    Json(req): Json<ChannelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.ensure_channel(&channel_id, &project);
    state.broker.subscribe(&req.name, &project, &channel_id);
    Ok(StatusCode::OK)
}

async fn unsubscribe_channel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    ProjectAuth { project }: ProjectAuth,
    Json(req): Json<ChannelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.unsubscribe(&req.name, &project, &channel_id);
    Ok(StatusCode::OK)
}

use crate::broker::state::{AgentState, BrokerState};
use crate::broker::DeliveryEngine;
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
        .route("/agents", get(list_agents))
        .route("/agents/register", post(register_agent))
        .route("/presence", put(update_presence))
        .route("/send", post(send_message))
        .route("/messages", get(get_messages))
        .route("/channels/{id}/subscribe", post(subscribe_channel))
        .route("/channels/{id}/unsubscribe", delete(unsubscribe_channel))
        .route("/health", get(health))
}

// --- Request/Response types ---

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub project: String,
    pub token: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub session_id: String,
}

#[derive(Deserialize)]
pub struct PresenceRequest {
    pub name: String,
    pub project: String,
    pub state: AgentState,
}

#[derive(Deserialize)]
pub struct SendRequest {
    pub from: String,
    pub from_project: String,
    pub to_agent: Option<String>,
    pub to_channel: Option<String>,
    pub body: String,
    pub metadata: Option<String>,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub message_id: String,
}

#[derive(Deserialize)]
pub struct AgentQuery {
    pub project: Option<String>,
    pub state: Option<String>,
}

#[derive(Deserialize)]
pub struct MessageQuery {
    pub name: String,
    pub project: String,
}

// --- Handlers ---

async fn health() -> &'static str {
    "ok"
}

async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, (StatusCode, String)> {
    // Verify token against registered agents
    {
        let conn = state.broker.db.conn();
        conn.execute(
            "INSERT OR REPLACE INTO agents (name, project, role, token, created_utc)
             VALUES (?1, ?2, ?3, ?4, datetime('now'))",
            rusqlite::params![req.name, req.project, req.role, req.token],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let _rx = state.broker.connect(&req.name, &req.project, &session_id).await;

    Ok(Json(RegisterResponse { session_id }))
}

async fn update_presence(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PresenceRequest>,
) -> StatusCode {
    state.broker.set_state(&req.name, &req.project, req.state).await;
    StatusCode::OK
}

async fn list_agents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AgentQuery>,
) -> Json<Vec<crate::broker::state::AgentInfo>> {
    let agents = state.broker.list_agents(query.project.as_deref()).await;
    Json(agents)
}

async fn send_message(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendRequest>,
) -> Result<Json<SendResponse>, (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    state
        .delivery
        .deliver(
            &id,
            &req.from,
            &req.from_project,
            req.to_agent.as_deref(),
            req.to_channel.as_deref(),
            &req.body,
            req.metadata.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(SendResponse { message_id: id }))
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MessageQuery>,
) -> Json<Vec<crate::broker::delivery::PendingMessage>> {
    let messages = state.delivery.drain_pending(&query.name, &query.project).await;
    Json(messages)
}

async fn subscribe_channel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    Json(req): Json<PresenceRequest>,
) -> StatusCode {
    let conn = state.broker.db.conn();
    // Ensure channel exists
    let _ = conn.execute(
        "INSERT OR IGNORE INTO channels (id, project) VALUES (?1, ?2)",
        rusqlite::params![channel_id, req.project],
    );
    let _ = conn.execute(
        "INSERT OR IGNORE INTO subscriptions (agent_name, project, channel_id) VALUES (?1, ?2, ?3)",
        rusqlite::params![req.name, req.project, channel_id],
    );
    StatusCode::OK
}

async fn unsubscribe_channel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    Json(req): Json<PresenceRequest>,
) -> StatusCode {
    let conn = state.broker.db.conn();
    let _ = conn.execute(
        "DELETE FROM subscriptions WHERE agent_name = ?1 AND project = ?2 AND channel_id = ?3",
        rusqlite::params![req.name, req.project, channel_id],
    );
    StatusCode::OK
}

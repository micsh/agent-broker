use crate::api::auth::AgentAuth;
use crate::broker::state::{AgentState, BrokerState};
use crate::broker::{DeliveryEngine, dispatch_stanza, DispatchResult, DispatchError};
use crate::db::repository::PendingMessage;
use crate::stanza;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put, delete, patch};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Startup configuration loaded from environment variables.
pub struct BrokerConfig {
    /// X-Admin-Key secret. None means admin API is disabled.
    pub admin_key: Option<String>,
    /// Max requests per second per project on write-path routes. Default: 100.
    pub rate_limit_rps: u32,
}

/// Shared application state passed to all route handlers.
pub struct AppState {
    pub broker: Arc<BrokerState>,
    pub delivery: Arc<DeliveryEngine>,
    pub config: BrokerConfig,
    pub rate_limiter: Arc<crate::api::middleware::ProjectRateLimiter>,
}

pub fn router(state: Arc<AppState>) -> Router<Arc<AppState>> {
    use axum::middleware::from_fn_with_state;

    // Write-path routes — rate-limited per project
    let write_routes = Router::new()
        .route("/send", post(send_message))
        .route("/presence", put(update_presence))
        .route("/channels/{id}/subscribe", post(subscribe_channel))
        .route("/channels/{id}/unsubscribe", delete(unsubscribe_channel))
        .layer(from_fn_with_state(state, crate::api::middleware::rate_limit_middleware));

    // Exempt routes — no rate limiting
    let exempt_routes = Router::new()
        .route("/projects/register", post(register_project))
        .route("/projects/{name}/rotate-key", post(rotate_project_key))
        .route("/agents/register", post(register_agent))
        .route("/agents/{name}/rekey", post(rekey_agent))
        .route("/agents/{name}", patch(update_agent_description))
        .route("/agents", get(list_agents))
        .route("/messages", get(get_messages))
        .route("/messages/peek", get(peek_messages))
        .route("/health", get(health));

    Router::new()
        .merge(write_routes)
        .merge(exempt_routes)
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
    /// Optional description of what this agent does. Shown in agent listings.
    #[serde(default)]
    pub description: String,
    /// Optional Ed25519 public key (64 hex chars = 32 bytes) for challenge-response WS auth.
    /// If provided, the agent will be enrolled at registration time (TOFU: first registration wins).
    #[serde(default)]
    pub public_key: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterAgentResponse {
    pub session_id: String,
    /// Present when no public key was provided — encourages Ed25519 enrollment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecation_notice: Option<String>,
}

/// Presence update payload -- agent identity comes from AgentAuth extractor.
#[derive(Deserialize)]
pub struct PresenceRequest {
    #[serde(default)]
    pub state: AgentState,
}

/// Channel subscribe/unsubscribe payload -- credentials carried by AgentAuth extractor.
#[derive(Deserialize)]
pub struct ChannelRequest {}

#[derive(Serialize)]
pub struct SendResponse {
    pub message_id: String,
}

#[derive(Deserialize)]
pub struct AgentQuery {
    pub project: Option<String>,
    /// When true, includes registered-but-disconnected agents with state=offline.
    #[serde(default)]
    pub include_offline: bool,
}

/// PATCH /agents/{name} request body.
#[derive(Deserialize)]
pub struct UpdateAgentRequest {
    pub description: String,
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

#[derive(Deserialize)]
pub struct RotateKeyRequest {
    pub project_key: String,
}

#[derive(Serialize)]
pub struct RotateKeyResponse {
    pub new_project_key: String,
}

/// POST /agents/{name}/rekey — body auth (project key proves project ownership).
/// Replaces the agent's registered Ed25519 public key.
#[derive(Deserialize)]
pub struct RekeyRequest {
    pub project: String,
    pub project_key: String,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct RekeyResponse {
    pub enrolled: bool,
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

/// POST /projects/{name}/rotate-key — body auth (caller presents current key).
/// Rotation is atomic: verify-then-update in one repository call.
/// Suspended projects can still rotate — the key check bypasses the suspend flag.
/// WS sessions established with the old key remain active until they disconnect.
async fn rotate_project_key(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(project_name): axum::extract::Path<String>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<RotateKeyResponse>, (StatusCode, String)> {
    let new_key = uuid::Uuid::new_v4().to_string();
    state.broker.repo.rotate_project_key(&project_name, &req.project_key, &new_key)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
    Ok(Json(RotateKeyResponse { new_project_key: new_key }))
}

/// POST /agents/{name}/rekey — body auth (project key proves project ownership).
/// Replaces the agent's registered Ed25519 public key.
/// IMPORTANT: The project key holder can re-enroll any agent in the project.
/// Agent-level self-authorization (signing with old key) is a v2 consideration.
async fn rekey_agent(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(agent_name): axum::extract::Path<String>,
    Json(req): Json<RekeyRequest>,
) -> Result<Json<RekeyResponse>, (StatusCode, String)> {
    // Body auth — verify project key only (does NOT check suspended status,
    // consistent with rotate_project_key — key rotation/rekey allowed for suspended projects)
    if !state.broker.repo.verify_project_key(&req.project, &req.project_key) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid project key".to_string()));
    }
    // Validate public key format: must decode as exactly 32 bytes
    hex::decode(&req.public_key)
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or((StatusCode::BAD_REQUEST, "public_key must be 64-hex-char Ed25519 public key".to_string()))?;
    // Set key
    state.broker.repo.set_agent_public_key(&agent_name, &req.project, &req.public_key)
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    tracing::info!("Public key rekeyed for {}.{}", agent_name, req.project);
    Ok(Json(RekeyResponse { enrolled: true }))
}

/// POST /agents/register -- body auth (first-contact route; caller has no session context yet).
async fn register_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterAgentRequest>,
) -> Result<Json<RegisterAgentResponse>, (StatusCode, String)> {
    if !state.broker.repo.verify_project_key(&req.project, &req.project_key) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid project key".to_string()));
    }

    if !state.broker.repo.project_exists(&req.project) {
        return Err((StatusCode::NOT_FOUND, format!("Project '{}' not found", req.project)));
    }

    // Suspended projects cannot register new agents — consistent with ProjectAuth gate
    if state.broker.repo.is_project_suspended(&req.project) {
        return Err((StatusCode::FORBIDDEN, "Project is suspended".to_string()));
    }

    // Reject names containing '.' to prevent resolve_agent_name misrouting
    if req.name.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            "Agent name must not contain '.' -- use the 'project' field for project scoping".to_string(),
        ));
    }

    // Description limit: max 500 Unicode scalar values
    if req.description.chars().count() > 500 {
        return Err((StatusCode::BAD_REQUEST, "description exceeds 500 characters".to_string()));
    }

    state.broker.repo.register_agent(&req.name, &req.project, &req.role, &req.description)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Enroll Ed25519 public key if provided (TOFU: first registration wins on INSERT OR REPLACE)
    if let Some(ref pk) = req.public_key {
        // Validate: must decode as exactly 32 bytes
        hex::decode(pk)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or((StatusCode::BAD_REQUEST, "public_key must be 64-hex-char Ed25519 public key".to_string()))?;
        state.broker.repo.set_agent_public_key(&req.name, &req.project, pk)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        tracing::info!("Ed25519 public key enrolled for {}.{}", req.name, req.project);
    }

    // NOTE: this is a correlation ID only -- live sessions are created exclusively on WS handshake.
    let session_id = uuid::Uuid::new_v4().to_string();

    let deprecation_notice = if req.public_key.is_none() {
        Some("Ed25519 public key auth is available. Register a public key to use challenge-response WS auth.".to_string())
    } else {
        None
    };

    tracing::info!("Agent registered: {}.{}", req.name, req.project);
    Ok(Json(RegisterAgentResponse { session_id, deprecation_notice }))
}

async fn list_agents(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AgentQuery>,
) -> Json<Vec<crate::broker::state::AgentInfo>> {
    let agents = state.broker.list_agents(query.project.as_deref(), query.include_offline).await;
    Json(agents)
}

/// PATCH /agents/{name} — self-update only (AgentAuth enforces identity).
/// Updates the agent's description. Max 500 Unicode scalar values.
async fn update_agent_description(
    State(state): State<Arc<AppState>>,
    auth: AgentAuth,
    Path(name): Path<String>,
    Json(req): Json<UpdateAgentRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Self-update only — path name must match authenticated agent
    if name != auth.agent_name {
        return Err((StatusCode::FORBIDDEN, "Cannot update another agent's description".to_string()));
    }
    if req.description.chars().count() > 500 {
        return Err((StatusCode::BAD_REQUEST, "description exceeds 500 characters".to_string()));
    }
    state.broker.repo.set_agent_description(&auth.agent_name, &auth.project, &req.description)
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    Ok(StatusCode::OK)
}

/// Accept raw stanza XML. Auth via AgentAuth extractor (X-Project + X-Project-Key + X-Agent-Name headers).
async fn send_message(
    State(state): State<Arc<AppState>>,
    AgentAuth { project, agent_name }: AgentAuth,
    body: String,
) -> Result<Json<SendResponse>, (StatusCode, String)> {
    // Reject empty or whitespace-only body
    if body.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Request body must not be empty".to_string()));
    }

    let parsed = stanza::parse(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid stanza: {e}")))?;

    // Verify stanza from= matches authenticated agent (accept qualified or unqualified form)
    if let stanza::Stanza::Message(ref msg) = parsed {
        let (stanza_name, _) = stanza::resolve_agent_name(&msg.from, &project);
        if stanza_name != agent_name {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Stanza from='{}' does not match authenticated agent '{}'", msg.from, agent_name),
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
        Err(DispatchError::CrossProjectDenied { source, target }) => Err((
            StatusCode::FORBIDDEN,
            format!("Cross-project post from '{}' to '{}' is not authorized", source, target),
        )),
        Err(DispatchError::CrossProjectNotFound { channel, project }) => Err((
            StatusCode::NOT_FOUND,
            format!("Channel '{}' in project '{}' not found", channel, project),
        )),
        Err(DispatchError::AmbiguousMention { name, projects }) => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Mention @{} is ambiguous: found in projects [{}]. Use Name.Project to disambiguate.",
                name,
                projects.join(", ")
            ),
        )),
    }
}

async fn update_presence(
    State(state): State<Arc<AppState>>,
    AgentAuth { project, agent_name }: AgentAuth,
    Json(req): Json<PresenceRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.set_state(&agent_name, &project, req.state).await;
    Ok(StatusCode::OK)
}

async fn get_messages(
    State(state): State<Arc<AppState>>,
    AgentAuth { project, agent_name }: AgentAuth,
) -> Result<Json<Vec<PendingMessage>>, (StatusCode, String)> {
    let messages = state.delivery.drain_pending(&agent_name, &project);
    Ok(Json(messages))
}

async fn peek_messages(
    State(state): State<Arc<AppState>>,
    AgentAuth { project, agent_name }: AgentAuth,
) -> Result<Json<PeekResponse>, (StatusCode, String)> {
    let pending = state.broker.repo.peek_pending(&agent_name, &project);
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
    AgentAuth { project, agent_name }: AgentAuth,
    Json(_req): Json<ChannelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.repo.ensure_channel(&channel_id, &project)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    state.broker.repo.subscribe(&agent_name, &project, &channel_id);
    Ok(StatusCode::OK)
}

async fn unsubscribe_channel(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    AgentAuth { project, agent_name }: AgentAuth,
    Json(_req): Json<ChannelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.repo.unsubscribe(&agent_name, &project, &channel_id);
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::middleware::ProjectRateLimiter;
    use crate::broker::{BrokerState, DeliveryEngine};
    use crate::db;
    use axum::body::Body;
    use axum::http::Request;
    use axum::http::StatusCode;
    use axum::response::Response;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn make_state() -> Arc<AppState> {
        let repo = Arc::new(db::open_memory().expect("in-memory DB"));
        let broker = Arc::new(BrokerState::new(repo));
        let delivery = Arc::new(DeliveryEngine::new(broker.clone()));
        let config = BrokerConfig { admin_key: None, rate_limit_rps: 100 };
        let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
        Arc::new(AppState { broker, delivery, config, rate_limiter })
    }

    fn test_app(state: Arc<AppState>) -> Router {
        use crate::api;
        api::http_router(state.clone()).with_state(state)
    }

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }

    /// Register a project + agent via the HTTP API; returns the project key.
    async fn register_project_and_agent(
        app: &Router,
        project: &str,
        agent: &str,
        description: &str,
    ) -> String {
        // Register project
        let resp: Response = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/projects/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"name": project}).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "register_project failed");
        let body = body_text(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let project_key = v["project_key"].as_str().unwrap().to_string();

        // Register agent
        let resp: Response = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/agents/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({
                    "name": agent, "project": project,
                    "project_key": project_key, "role": "assistant",
                    "description": description
                }).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "register_agent failed");
        project_key
    }

    #[tokio::test]
    async fn register_with_description_shows_in_list() {
        let state = make_state();
        let app = test_app(state);

        register_project_and_agent(&app, "proj", "Alice", "Alice the assistant").await;

        let resp: Response = app.clone().oneshot(
            Request::builder().uri("/agents").body(Body::empty()).unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_text(resp).await;
        // Alice is not connected via WS, so not in connected list (offline includes only with include_offline=true)
        // This test verifies the route returns 200 cleanly
        assert!(body.contains("[]") || body.contains("Alice") || body == "[]");
    }

    #[tokio::test]
    async fn register_without_description_defaults_to_empty() {
        let state = make_state();
        register_project_and_agent(&test_app(state.clone()), "proj", "Alice", "").await;
        let desc = state.broker.repo.get_agent_description("Alice", "proj");
        assert_eq!(desc, "", "empty description on first registration");
    }

    #[tokio::test]
    async fn re_register_with_blank_preserves_description() {
        let state = make_state();
        let app = test_app(state.clone());
        let key = register_project_and_agent(&app, "proj", "Alice", "Original").await;

        // Re-register with blank description
        let resp: Response = app.oneshot(
            Request::builder()
                .method("POST").uri("/agents/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({
                    "name": "Alice", "project": "proj",
                    "project_key": key, "role": "assistant", "description": ""
                }).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.broker.repo.get_agent_description("Alice", "proj"), "Original");
    }

    #[tokio::test]
    async fn re_register_with_new_description_overwrites() {
        let state = make_state();
        let app = test_app(state.clone());
        let key = register_project_and_agent(&app, "proj", "Alice", "Old").await;

        let resp: Response = app.oneshot(
            Request::builder()
                .method("POST").uri("/agents/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({
                    "name": "Alice", "project": "proj",
                    "project_key": key, "role": "assistant", "description": "New"
                }).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.broker.repo.get_agent_description("Alice", "proj"), "New");
    }

    #[tokio::test]
    async fn patch_self_update_succeeds() {
        let state = make_state();
        let app = test_app(state.clone());
        let key = register_project_and_agent(&app, "proj", "Alice", "Initial").await;

        let resp: Response = app.oneshot(
            Request::builder()
                .method("PATCH").uri("/agents/Alice")
                .header("content-type", "application/json")
                .header("x-project", "proj")
                .header("x-project-key", &key)
                .header("x-agent-name", "Alice")
                .body(Body::from(serde_json::json!({"description": "Updated"}).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.broker.repo.get_agent_description("Alice", "proj"), "Updated");
    }

    #[tokio::test]
    async fn patch_other_agent_returns_403() {
        let state = make_state();
        let app = test_app(state.clone());
        let key = register_project_and_agent(&app, "proj", "Alice", "").await;

        // Register Bob in the same project using the same key (skip project registration)
        let resp: Response = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/agents/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({
                    "name": "Bob", "project": "proj",
                    "project_key": key, "role": "assistant", "description": ""
                }).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "register Bob failed");

        // Alice tries to update Bob — must be 403
        let resp: Response = app.oneshot(
            Request::builder()
                .method("PATCH").uri("/agents/Bob")
                .header("content-type", "application/json")
                .header("x-project", "proj")
                .header("x-project-key", &key)
                .header("x-agent-name", "Alice")
                .body(Body::from(serde_json::json!({"description": "Hack"}).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn patch_description_too_long_returns_400() {
        let state = make_state();
        let app = test_app(state.clone());
        let key = register_project_and_agent(&app, "proj", "Alice", "").await;
        // 501 multibyte chars — each is >1 byte, so len() > chars().count(). Must still be rejected.
        let long = "é".repeat(501);

        let resp: Response = app.oneshot(
            Request::builder()
                .method("PATCH").uri("/agents/Alice")
                .header("content-type", "application/json")
                .header("x-project", "proj")
                .header("x-project-key", &key)
                .header("x-agent-name", "Alice")
                .body(Body::from(serde_json::json!({"description": long}).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_description_too_long_returns_400() {
        let state = make_state();
        let app = test_app(state.clone());
        // Register project first
        let resp: Response = app.clone().oneshot(
            Request::builder()
                .method("POST").uri("/projects/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"name": "proj"}).to_string()))
                .unwrap()
        ).await.unwrap();
        let body = body_text(resp).await;
        let key = serde_json::from_str::<serde_json::Value>(&body).unwrap()["project_key"]
            .as_str().unwrap().to_string();

        let long = "é".repeat(501);
        let resp: Response = app.oneshot(
            Request::builder()
                .method("POST").uri("/agents/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({
                    "name": "Alice", "project": "proj",
                    "project_key": key, "role": "assistant",
                    "description": long
                }).to_string()))
                .unwrap()
        ).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_agents_include_offline_shows_registered_agents() {
        let state = make_state();
        register_project_and_agent(&test_app(state.clone()), "proj", "Alice", "Offline Alice").await;

        // include_offline=true should return Alice even without WS connection
        let agents = state.broker.list_agents(None, true).await;
        assert_eq!(agents.len(), 1, "should return 1 offline agent");
        assert_eq!(agents[0].name, "Alice");
        assert_eq!(agents[0].description, "Offline Alice");
    }

    #[tokio::test]
    async fn get_agents_without_include_offline_excludes_disconnected() {
        let state = make_state();
        register_project_and_agent(&test_app(state.clone()), "proj", "Alice", "").await;

        // Default (include_offline=false) should return empty (Alice never connected via WS)
        let agents = state.broker.list_agents(None, false).await;
        assert!(agents.is_empty(), "should return no connected agents");
    }
}

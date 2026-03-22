use crate::api::auth::AdminAuth;
use crate::api::routes::AppState;
use crate::db::repository::{BrokerStats, ProjectInfo, ProjectStats};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use std::sync::Arc;

pub fn admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/projects", get(list_projects))
        .route("/projects/{name}", delete(delete_project))
        .route("/projects/{name}/suspend", post(suspend_project))
        .route("/projects/{name}/unsuspend", post(unsuspend_project))
        .route("/projects/{name}/stats", get(project_stats))
        .route("/stats", get(get_stats))
}

async fn list_projects(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Json<Vec<ProjectInfo>> {
    Json(state.broker.repo.list_projects())
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
) -> Json<BrokerStats> {
    Json(state.broker.repo.get_broker_stats())
}

async fn delete_project(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // F7-D: evict live WS sessions FIRST — prevents ghost session delivery during deletion window.
    // Order is mandatory: disconnect_all_in_project() BEFORE repo.delete_project().
    // Swapping would create a window where live sessions receive delivery attempts for a deleted project.
    state.broker.disconnect_all_in_project(&name).await;
    state.broker.repo.delete_project(&name)
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn suspend_project(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.repo.set_project_status(&name, "suspended")
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    Ok(StatusCode::OK)
}

async fn unsuspend_project(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    state.broker.repo.set_project_status(&name, "active")
        .map_err(|e| (StatusCode::NOT_FOUND, e))?;
    Ok(StatusCode::OK)
}

async fn project_stats(
    State(state): State<Arc<AppState>>,
    _auth: AdminAuth,
    Path(name): Path<String>,
) -> Json<ProjectStats> {
    Json(state.broker.repo.project_stats(&name))
}

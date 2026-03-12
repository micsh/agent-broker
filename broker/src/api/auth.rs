use crate::api::routes::AppState;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use std::sync::Arc;

/// Axum extractor that validates X-Project + X-Project-Key headers and returns
/// a typed ProjectAuth on success. Eliminates duplicated auth logic across routes.
pub struct ProjectAuth {
    pub project: String,
}

impl FromRequestParts<Arc<AppState>> for ProjectAuth {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let project = parts
            .headers
            .get("x-project")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::BAD_REQUEST, "Missing X-Project header".to_string()))?;
        let key = parts
            .headers
            .get("x-project-key")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::BAD_REQUEST, "Missing X-Project-Key header".to_string()))?;
        if !state.broker.verify_project_key(project, key) {
            return Err((StatusCode::UNAUTHORIZED, "Invalid project key".to_string()));
        }
        Ok(ProjectAuth {
            project: project.to_string(),
        })
    }
}

/// Extends ProjectAuth with authenticated agent identity.
/// Reads X-Agent-Name header and verifies the agent exists in the project.
pub struct AgentAuth {
    pub project: String,
    pub agent_name: String,
}

impl FromRequestParts<Arc<AppState>> for AgentAuth {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Reuse ProjectAuth for project + key verification
        let ProjectAuth { project } = ProjectAuth::from_request_parts(parts, state).await?;

        let agent_name = parts
            .headers
            .get("x-agent-name")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::BAD_REQUEST, "Missing X-Agent-Name header".to_string()))?;

        if !state.broker.agent_exists(agent_name, &project) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Agent '{}' not registered in project '{}'", agent_name, project),
            ));
        }

        Ok(AgentAuth {
            project,
            agent_name: agent_name.to_string(),
        })
    }
}

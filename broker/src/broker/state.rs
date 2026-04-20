use crate::broker::nonce::NonceStore;
use crate::db::Repository;
use crate::stanza::PresenceStatus;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Connected agent session — holds the WebSocket sender for live push.
#[derive(Debug, Clone)]
pub struct AgentSession {
    pub name: String,
    pub project: String,
    pub state: AgentState,
    pub tx: broadcast::Sender<String>,
}

/// Agent presence state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentState {
    #[default]
    Available,
    Busy,
    Offline,
}

impl std::fmt::Display for AgentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentState::Available => write!(f, "available"),
            AgentState::Busy => write!(f, "busy"),
            AgentState::Offline => write!(f, "offline"),
        }
    }
}

impl From<PresenceStatus> for AgentState {
    fn from(status: PresenceStatus) -> Self {
        match status {
            PresenceStatus::Available => AgentState::Available,
            PresenceStatus::Busy => AgentState::Busy,
            PresenceStatus::Offline => AgentState::Offline,
        }
    }
}

/// Composite key for an agent: name + project.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AgentKey {
    pub name: String,
    pub project: String,
}

impl AgentKey {
    pub fn new(name: &str, project: &str) -> Self {
        Self {
            name: name.to_string(),
            project: project.to_string(),
        }
    }
}

/// Shared broker state — in-memory connected agents + repository for persistence.
pub struct BrokerState {
    pub(crate) repo: Arc<Repository>,
    pub sessions: RwLock<HashMap<AgentKey, AgentSession>>,
    /// In-memory nonce store for Ed25519 challenge-response handshakes.
    pub nonce_store: NonceStore,
}

impl BrokerState {
    pub fn new(repo: Arc<Repository>) -> Self {
        Self {
            repo,
            sessions: RwLock::new(HashMap::new()),
            nonce_store: NonceStore::new(),
        }
    }

    /// Authenticate an agent: verify project key and check agent registration.
    /// Returns Ok(()) on success, Err(reason) on failure.
    pub fn authenticate(&self, name: &str, project: &str, key: &str) -> Result<(), String> {
        if !self.repo.verify_project_key(project, key) {
            return Err("Invalid project key".to_string());
        }
        if !self.repo.agent_exists(name, project) {
            return Err(format!("Agent '{}' not registered in project '{}'", name, project));
        }
        Ok(())
    }

    // --- Session management ---

    /// Register an agent connection. Returns a broadcast receiver for live messages.
    ///
    /// Returns `Err(())` if a session for this identity is already active — caller must
    /// send a 409 Conflict frame and close the connection.
    pub async fn connect(
        &self,
        name: &str,
        project: &str,
    ) -> Result<broadcast::Receiver<String>, ()> {
        let key = AgentKey::new(name, project);
        let mut sessions = self.sessions.write().await;
        if sessions.contains_key(&key) {
            tracing::warn!("Duplicate connect rejected: {}.{}", name, project);
            return Err(());
        }
        let (tx, rx) = broadcast::channel(64);
        let session = AgentSession {
            name: name.to_string(),
            project: project.to_string(),
            state: AgentState::Available,
            tx,
        };
        sessions.insert(key, session);
        tracing::info!("Agent connected: {}.{}", name, project);
        Ok(rx)
    }

    /// Disconnect an agent.
    pub async fn disconnect(&self, name: &str, project: &str) {
        let key = AgentKey::new(name, project);
        let mut sessions = self.sessions.write().await;
        sessions.remove(&key);

        tracing::info!("Agent disconnected: {}.{}", name, project);
    }

    /// Remove all live WS sessions for agents in the given project.
    /// Must be called BEFORE delete_project() to avoid ghost session delivery during the deletion window.
    pub async fn disconnect_all_in_project(&self, project: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|key, _| key.project != project);
        tracing::info!("Disconnected all sessions for project '{}'", project);
    }

    /// Update agent presence state.
    pub async fn set_state(&self, name: &str, project: &str, state: AgentState) {
        let key = AgentKey::new(name, project);
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&key) {
            session.state = state;
        }
    }

    /// Get all agents, optionally filtered by project.
    /// Connected agents are always included; offline (DB-registered) agents included when include_offline=true.
    /// Description is always enriched from the DB.
    pub async fn list_agents(&self, project_filter: Option<&str>, include_offline: bool) -> Vec<AgentInfo> {
        let sessions = self.sessions.read().await;
        let mut result: Vec<AgentInfo> = sessions
            .values()
            .filter(|s| project_filter.map_or(true, |p| s.project == p))
            .map(|s| AgentInfo {
                name: s.name.clone(),
                project: s.project.clone(),
                state: s.state,
                // N DB reads (one per connected agent) — acceptable at broker scale.
                // Batch with WHERE name IN (...) if contention becomes an issue.
                description: self.repo.get_agent_description(&s.name, &s.project),
            })
            .collect();

        if include_offline {
            // Build set of connected (name, project) keys to avoid duplicates
            let connected: std::collections::HashSet<(String, String)> =
                result.iter().map(|a| (a.name.clone(), a.project.clone())).collect();
            // Synthesise offline entries for agents in DB but not in sessions
            let registered = self.repo.list_registered_agents(project_filter);
            for (name, project, description) in registered {
                if !connected.contains(&(name.clone(), project.clone())) {
                    result.push(AgentInfo {
                        name,
                        project,
                        state: AgentState::Offline,
                        description,
                    });
                }
            }
        }
        result
    }

    /// Send a message to a specific agent. Returns true if delivered live.
    pub async fn send_to_agent(&self, name: &str, project: &str, message: &str) -> bool {
        let key = AgentKey::new(name, project);
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&key) {
            session.tx.send(message.to_string()).is_ok()
        } else {
            false
        }
    }

    /// Broadcast a message to all agents on a channel within the given project.
    /// Returns per-subscriber delivery results: (name, project, delivered).
    pub async fn send_to_channel(
        &self,
        channel_id: &str,
        project: &str,
        message: &str,
        exclude: Option<&str>,
    ) -> Vec<(String, String, bool)> {
        let subscribers = self.repo.get_subscribers(channel_id, project);
        let sessions = self.sessions.read().await;
        let mut results = Vec::new();
        for (name, proj) in subscribers {
            if exclude.is_some_and(|e| e == name) {
                continue;
            }
            let key = AgentKey::new(&name, &proj);
            let delivered = match sessions.get(&key) {
                Some(session) => session.tx.send(message.to_string()).is_ok(),
                None => false,
            };
            results.push((name, proj, delivered));
        }
        results
    }
}

/// Public agent info for discovery responses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInfo {
    pub name: String,
    pub project: String,
    pub state: AgentState,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn make_state() -> Arc<BrokerState> {
        let repo = Arc::new(db::open_memory().expect("in-memory DB"));
        Arc::new(BrokerState::new(repo))
    }

    /// Fresh connect succeeds and returns a working receiver.
    #[tokio::test]
    async fn connect_fresh_returns_ok() {
        let state = make_state();
        assert!(state.connect("Alice", "proj").await.is_ok());
    }

    /// Duplicate connect (same name+project) is rejected with Err(()).
    #[tokio::test]
    async fn connect_duplicate_returns_err() {
        let state = make_state();
        assert!(state.connect("Alice", "proj").await.is_ok());
        assert!(
            state.connect("Alice", "proj").await.is_err(),
            "second connect for same identity must return Err(())"
        );
    }

    /// Different identities in the same project do NOT conflict.
    #[tokio::test]
    async fn connect_different_agents_in_same_project_both_ok() {
        let state = make_state();
        assert!(state.connect("Alice", "proj").await.is_ok());
        assert!(state.connect("Bob", "proj").await.is_ok());
    }

    /// Same name but different project does NOT conflict.
    #[tokio::test]
    async fn connect_same_name_different_project_ok() {
        let state = make_state();
        assert!(state.connect("Alice", "proj-a").await.is_ok());
        assert!(state.connect("Alice", "proj-b").await.is_ok());
    }

    /// After disconnect, the same identity can reconnect.
    #[tokio::test]
    async fn connect_after_disconnect_ok() {
        let state = make_state();
        assert!(state.connect("Alice", "proj").await.is_ok());
        state.disconnect("Alice", "proj").await;
        assert!(
            state.connect("Alice", "proj").await.is_ok(),
            "must be able to reconnect after disconnect"
        );
    }
}

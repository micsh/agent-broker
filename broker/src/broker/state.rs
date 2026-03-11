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
}

impl BrokerState {
    pub fn new(repo: Arc<Repository>) -> Self {
        Self {
            repo,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    // --- Delegated repository methods ---

    pub fn verify_project_key(&self, project: &str, key: &str) -> bool {
        self.repo.verify_project_key(project, key)
    }

    pub fn register_project(&self, name: &str, key: &str) -> Result<(), String> {
        self.repo.register_project(name, key)
    }

    pub fn register_agent(&self, name: &str, project: &str, role: &str) -> Result<(), String> {
        self.repo.register_agent(name, project, role)
    }

    pub fn agent_exists(&self, name: &str, project: &str) -> bool {
        self.repo.agent_exists(name, project)
    }

    pub fn project_exists(&self, name: &str) -> bool {
        self.repo.project_exists(name)
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

    pub fn ensure_channel(&self, id: &str, project: &str) {
        self.repo.ensure_channel(id, project)
    }

    pub fn subscribe(&self, agent_name: &str, project: &str, channel_id: &str) {
        self.repo.subscribe(agent_name, project, channel_id)
    }

    pub fn unsubscribe(&self, agent_name: &str, project: &str, channel_id: &str) {
        self.repo.unsubscribe(agent_name, project, channel_id)
    }

    pub fn peek_pending(&self, name: &str, project: &str) -> Vec<(String, String, String)> {
        self.repo.peek_pending(name, project)
    }

    // --- Session management ---

    /// Register an agent connection. Returns a broadcast receiver for live messages.
    pub async fn connect(
        &self,
        name: &str,
        project: &str,
    ) -> broadcast::Receiver<String> {
        let (tx, rx) = broadcast::channel(64);
        let key = AgentKey::new(name, project);
        let session = AgentSession {
            name: name.to_string(),
            project: project.to_string(),
            state: AgentState::Available,
            tx,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(key, session);

        tracing::info!("Agent connected: {}.{}", name, project);
        rx
    }

    /// Disconnect an agent.
    pub async fn disconnect(&self, name: &str, project: &str) {
        let key = AgentKey::new(name, project);
        let mut sessions = self.sessions.write().await;
        sessions.remove(&key);

        tracing::info!("Agent disconnected: {}.{}", name, project);
    }

    /// Update agent presence state.
    pub async fn set_state(&self, name: &str, project: &str, state: AgentState) {
        let key = AgentKey::new(name, project);
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(&key) {
            session.state = state;
        }
    }

    /// Get all connected agents, optionally filtered by project.
    pub async fn list_agents(&self, project_filter: Option<&str>) -> Vec<AgentInfo> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|s| match project_filter {
                Some(p) => s.project == p,
                None => true,
            })
            .map(|s| AgentInfo {
                name: s.name.clone(),
                project: s.project.clone(),
                state: s.state,
            })
            .collect()
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
    pub async fn send_to_channel(&self, channel_id: &str, project: &str, message: &str, exclude: Option<&str>) {
        let subscribers = self.repo.get_subscribers(channel_id, project);

        let sessions = self.sessions.read().await;
        for (name, project) in subscribers {
            if exclude.is_some_and(|e| e == name) {
                continue;
            }
            let key = AgentKey::new(&name, &project);
            if let Some(session) = sessions.get(&key) {
                let _ = session.tx.send(message.to_string());
            }
        }
    }
}

/// Public agent info for discovery responses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInfo {
    pub name: String,
    pub project: String,
    pub state: AgentState,
}

use crate::db::Db;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Connected agent session — holds the WebSocket sender for live push.
#[derive(Debug, Clone)]
pub struct AgentSession {
    pub name: String,
    pub project: String,
    pub session_id: String,
    pub state: AgentState,
    pub tx: broadcast::Sender<String>,
}

/// Agent presence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentState {
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

    /// Display as Name.Project.
    pub fn display(&self) -> String {
        format!("{}.{}", self.name, self.project)
    }
}

/// Shared broker state — in-memory connected agents + database handle.
pub struct BrokerState {
    pub db: Arc<Db>,
    pub sessions: RwLock<HashMap<AgentKey, AgentSession>>,
}

impl BrokerState {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            db,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Register an agent connection. Returns a broadcast receiver for live messages.
    pub async fn connect(
        &self,
        name: &str,
        project: &str,
        session_id: &str,
    ) -> broadcast::Receiver<String> {
        let (tx, rx) = broadcast::channel(64);
        let key = AgentKey::new(name, project);
        let session = AgentSession {
            name: name.to_string(),
            project: project.to_string(),
            session_id: session_id.to_string(),
            state: AgentState::Available,
            tx,
        };

        let mut sessions = self.sessions.write().await;
        sessions.insert(key, session);

        tracing::info!("Agent connected: {}.{} (session: {})", name, project, session_id);
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

    /// Broadcast a message to all agents on a channel.
    pub async fn send_to_channel(&self, channel_id: &str, message: &str, exclude: Option<&str>) {
        let subscribers = {
            let conn = self.db.conn();
            let mut stmt = conn
                .prepare(
                    "SELECT agent_name, project FROM subscriptions WHERE channel_id = ?1",
                )
                .unwrap();
            let rows: Vec<(String, String)> = stmt
                .query_map(rusqlite::params![channel_id], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            rows
        };

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

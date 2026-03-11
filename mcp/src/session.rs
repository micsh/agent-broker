use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Authenticated session state for a registered MCP client.
pub struct Session {
    pub project: String,
    pub project_key: String,
    pub agent_name: String,
    pub broker_url: String,
}

/// Manages MCP session state and all filesystem I/O for credential/identity persistence.
/// Zero dependency on rmcp, reqwest, or any broker module — pure std + serde_json + dirs.
#[derive(Clone)]
pub struct SessionManager {
    state: Arc<Mutex<Option<Session>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
        }
    }

    /// Set session after successful registration.
    pub fn register(
        &self,
        agent_name: String,
        project: String,
        project_key: String,
        broker_url: String,
    ) {
        save_key(&project, &project_key);
        if let Ok(cwd) = std::env::current_dir() {
            save_identity(&cwd.to_string_lossy(), &agent_name);
        }
        *self.state.lock().unwrap() = Some(Session {
            project,
            project_key,
            agent_name,
            broker_url,
        });
    }

    /// Return (agent_name, project, project_key, broker_url) or an error if not registered.
    pub fn get(&self) -> Result<(String, String, String, String), rmcp::ErrorData> {
        let g = self.state.lock().unwrap();
        match g.as_ref() {
            Some(s) => Ok((
                s.agent_name.clone(),
                s.project.clone(),
                s.project_key.clone(),
                s.broker_url.clone(),
            )),
            None => Err(rmcp::ErrorData::invalid_params(
                "Not registered. Call broker_register first.",
                None,
            )),
        }
    }
}

// --- Filesystem helpers ---

/// Key file path: ~/.agent-broker/keys/<project>.key
pub fn key_file_path(project: &str) -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".agent-broker").join("keys").join(format!("{project}.key"))
}

pub fn load_key(project: &str) -> Option<String> {
    std::fs::read_to_string(key_file_path(project))
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn save_key(project: &str, key: &str) {
    let path = key_file_path(project);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, key);
}

/// Identity file: ~/.agent-broker/identities.json — maps CWD → agent name
pub fn identities_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".agent-broker").join("identities.json")
}

pub fn load_identities() -> std::collections::HashMap<String, String> {
    std::fs::read_to_string(identities_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_identity(cwd: &str, name: &str) {
    let mut map = load_identities();
    map.insert(cwd.to_string(), name.to_string());
    let path = identities_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, serde_json::to_string_pretty(&map).unwrap_or_default());
}

pub fn lookup_identity() -> Option<String> {
    let cwd = std::env::current_dir().ok()?.to_string_lossy().to_string();
    load_identities().get(&cwd).cloned()
}

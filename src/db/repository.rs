use rusqlite::params;
use crate::identity;
use std::sync::Mutex;

/// Central repository for all database operations.
/// All SQL lives here — no direct DB access outside this module.
pub struct Repository {
    conn: Mutex<rusqlite::Connection>,
}

// --- Types ---

#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingMessage {
    pub id: String,
    pub from_agent: String,
    pub from_project: String,
    pub body: String,
    pub metadata: Option<String>,
    pub created_utc: String,
}

impl Repository {
    pub fn new(conn: rusqlite::Connection) -> Self {
        Self { conn: Mutex::new(conn) }
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
        self.conn.lock().expect("database lock poisoned")
    }

    // --- Projects ---

    /// Register a new project. Returns error if project already exists.
    pub fn register_project(&self, name: &str, key: &str) -> Result<(), String> {
        let key_hash = identity::hash_key(key);
        self.conn().execute(
            "INSERT INTO projects (name, key_hash) VALUES (?1, ?2)",
            params![name, key_hash],
        ).map_err(|e| format!("Failed to register project (already exists?): {e}"))?;
        Ok(())
    }

    /// Verify a project key. Returns true if the key matches.
    pub fn verify_project_key(&self, project: &str, key: &str) -> bool {
        let conn = self.conn();
        let stored: Option<String> = conn
            .prepare("SELECT key_hash FROM projects WHERE name = ?1")
            .ok()
            .and_then(|mut stmt| {
                stmt.query_row(params![project], |row: &rusqlite::Row| row.get(0)).ok()
            });
        match stored {
            Some(stored_hash) => identity::verify_key_hash(key, &stored_hash),
            None => false,
        }
    }

    /// Check if a project exists.
    pub fn project_exists(&self, name: &str) -> bool {
        let conn = self.conn();
        conn.prepare("SELECT 1 FROM projects WHERE name = ?1")
            .ok()
            .and_then(|mut stmt| stmt.query_row(params![name], |_| Ok(())).ok())
            .is_some()
    }

    // --- Agents ---

    /// Register or update an agent within a project.
    pub fn register_agent(&self, name: &str, project: &str, role: &str) -> Result<(), String> {
        self.conn().execute(
            "INSERT OR REPLACE INTO agents (name, project, role, created_utc)
             VALUES (?1, ?2, ?3, datetime('now'))",
            params![name, project, role],
        ).map_err(|e| format!("Failed to register agent: {e}"))?;
        Ok(())
    }

    /// Check if an agent is registered.
    pub fn agent_exists(&self, name: &str, project: &str) -> bool {
        let conn = self.conn();
        conn.prepare("SELECT 1 FROM agents WHERE name = ?1 AND project = ?2")
            .ok()
            .and_then(|mut stmt| stmt.query_row(params![name, project], |_| Ok(())).ok())
            .is_some()
    }

    // --- Channels ---

    pub fn ensure_channel(&self, id: &str, project: &str) {
        let _ = self.conn().execute(
            "INSERT OR IGNORE INTO channels (id, project) VALUES (?1, ?2)",
            params![id, project],
        );
    }

    pub fn subscribe(&self, agent_name: &str, project: &str, channel_id: &str) {
        let _ = self.conn().execute(
            "INSERT OR IGNORE INTO subscriptions (agent_name, project, channel_id) VALUES (?1, ?2, ?3)",
            params![agent_name, project, channel_id],
        );
    }

    pub fn unsubscribe(&self, agent_name: &str, project: &str, channel_id: &str) {
        let _ = self.conn().execute(
            "DELETE FROM subscriptions WHERE agent_name = ?1 AND project = ?2 AND channel_id = ?3",
            params![agent_name, project, channel_id],
        );
    }

    pub fn get_subscribers(&self, channel_id: &str) -> Vec<(String, String)> {
        let conn = self.conn();
        let mut stmt = match conn.prepare(
            "SELECT agent_name, project FROM subscriptions WHERE channel_id = ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(params![channel_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    // --- Messages ---

    pub fn insert_message(
        &self,
        id: &str,
        from_agent: &str,
        from_project: &str,
        to_agent: Option<&str>,
        to_channel: Option<&str>,
        body: &str,
        metadata: Option<&str>,
    ) -> Result<(), String> {
        self.conn().execute(
            "INSERT INTO messages (id, from_agent, from_project, to_agent, to_channel, body, metadata, created_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))",
            params![id, from_agent, from_project, to_agent, to_channel, body, metadata],
        ).map_err(|e| format!("Failed to persist message: {e}"))?;
        Ok(())
    }

    pub fn record_pending(&self, message_id: &str, agent: &str, project: &str) -> Result<(), String> {
        self.conn().execute(
            "INSERT OR IGNORE INTO delivery_log (message_id, agent_name, project, status)
             VALUES (?1, ?2, ?3, 'pending')",
            params![message_id, agent, project],
        ).map_err(|e| format!("Failed to record pending: {e}"))?;
        Ok(())
    }

    pub fn record_delivered(&self, message_id: &str, agent: &str, project: &str) -> Result<(), String> {
        self.conn().execute(
            "INSERT OR REPLACE INTO delivery_log (message_id, agent_name, project, status, delivered_utc)
             VALUES (?1, ?2, ?3, 'delivered', datetime('now'))",
            params![message_id, agent, project],
        ).map_err(|e| format!("Failed to record delivery: {e}"))?;
        Ok(())
    }

    pub fn drain_pending(&self, name: &str, project: &str) -> Vec<PendingMessage> {
        let conn = self.conn();
        let mut stmt = match conn.prepare(
            "SELECT m.id, m.from_agent, m.from_project, m.body, m.metadata, m.created_utc
             FROM delivery_log dl
             JOIN messages m ON dl.message_id = m.id
             WHERE dl.agent_name = ?1 AND dl.project = ?2 AND dl.status = 'pending'
             ORDER BY m.created_utc ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let messages: Vec<PendingMessage> = match stmt
            .query_map(params![name, project], |row| {
                Ok(PendingMessage {
                    id: row.get(0)?,
                    from_agent: row.get(1)?,
                    from_project: row.get(2)?,
                    body: row.get(3)?,
                    metadata: row.get(4)?,
                    created_utc: row.get(5)?,
                })
            }) {
                Ok(r) => r.filter_map(|r| r.ok()).collect(),
                Err(_) => return Vec::new(),
            };

        if !messages.is_empty() {
            let _ = conn.execute(
                "UPDATE delivery_log SET status = 'delivered', delivered_utc = datetime('now')
                 WHERE agent_name = ?1 AND project = ?2 AND status = 'pending'",
                params![name, project],
            );
        }

        messages
    }

    pub fn cleanup(&self, delivered_hours: u64, pending_hours: u64) -> (usize, usize) {
        let conn = self.conn();

        let delivered_deleted = conn.execute(
            "DELETE FROM messages WHERE id IN (
                SELECT m.id FROM messages m
                JOIN delivery_log dl ON dl.message_id = m.id
                WHERE dl.status = 'delivered'
                AND dl.delivered_utc < datetime('now', ?1)
            )",
            params![format!("-{delivered_hours} hours")],
        ).unwrap_or(0);

        let _ = conn.execute(
            "DELETE FROM delivery_log WHERE message_id NOT IN (SELECT id FROM messages)",
            [],
        );

        let pending_deleted = conn.execute(
            "DELETE FROM messages WHERE id IN (
                SELECT m.id FROM messages m
                JOIN delivery_log dl ON dl.message_id = m.id
                WHERE dl.status = 'pending'
                AND m.created_utc < datetime('now', ?1)
            )",
            params![format!("-{pending_hours} hours")],
        ).unwrap_or(0);

        let _ = conn.execute(
            "DELETE FROM delivery_log WHERE message_id NOT IN (SELECT id FROM messages)",
            [],
        );

        (delivered_deleted, pending_deleted)
    }
}

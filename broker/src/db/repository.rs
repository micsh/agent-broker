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

/// Project summary for admin listing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectInfo {
    pub name: String,
    pub status: String,
    pub created_utc: String,
    pub agent_count: i64,
    pub pending_count: i64,
}

/// Per-project statistics for admin inspection.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectStats {
    pub agent_count: i64,
    pub message_count: i64,
    pub pending_count: i64,
}

/// Broker-wide statistics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BrokerStats {
    pub project_count: i64,
    pub agent_count: i64,
    pub pending_count: i64,
}

/// Project lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectStatus {
    Active,
    Suspended,
}

impl ProjectStatus {
    fn as_str(self) -> &'static str {
        match self {
            ProjectStatus::Active => "active",
            ProjectStatus::Suspended => "suspended",
        }
    }
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
        self.seed_cross_project_default(name);
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

    // --- Admin: project status ---

    /// Returns true if the project exists and its status is `Suspended`.
    /// Returns false if the project is not found.
    pub fn is_project_suspended(&self, name: &str) -> bool {
        let conn = self.conn();
        let status: Option<String> = conn
            .prepare("SELECT status FROM projects WHERE name = ?1")
            .ok()
            .and_then(|mut stmt| stmt.query_row(params![name], |row| row.get(0)).ok());
        match status {
            Some(s) => s == ProjectStatus::Suspended.as_str(),
            None => false,
        }
    }

    /// Set the status of a project.
    /// Returns Err if the project does not exist (0 rows affected).
    pub fn set_project_status(&self, name: &str, status: ProjectStatus) -> Result<(), String> {
        let rows = self.conn().execute(
            "UPDATE projects SET status = ?1 WHERE name = ?2",
            params![status.as_str(), name],
        ).map_err(|e| format!("Failed to set project status: {e}"))?;
        if rows == 0 {
            return Err(format!("Project '{}' not found", name));
        }
        Ok(())
    }

    /// Rotate the project key atomically.
    /// Verifies the old key via raw hash comparison (bypasses suspend check — suspended projects
    /// must still be rotatable). Returns Err if the old key is wrong or the project is not found.
    pub fn rotate_project_key(&self, name: &str, old_key: &str, new_key: &str) -> Result<(), String> {
        // Raw hash comparison — intentionally does NOT call verify_project_key, which would
        // return false for suspended projects after the suspend check was added.
        let stored_hash: Option<String> = {
            let conn = self.conn();
            conn.prepare("SELECT key_hash FROM projects WHERE name = ?1")
                .ok()
                .and_then(|mut stmt| stmt.query_row(params![name], |row| row.get(0)).ok())
        };
        match stored_hash {
            None => return Err(format!("Project '{}' not found", name)),
            Some(hash) if !identity::verify_key_hash(old_key, &hash) => {
                return Err("Invalid current key".to_string());
            }
            _ => {}
        }
        let new_hash = identity::hash_key(new_key);
        let rows = self.conn().execute(
            "UPDATE projects SET key_hash = ?1 WHERE name = ?2",
            params![new_hash, name],
        ).map_err(|e| format!("Failed to rotate key: {e}"))?;
        if rows == 0 {
            return Err(format!("Project '{}' not found", name));
        }
        Ok(())
    }

    // --- Admin: queries ---

    /// List all projects with summary statistics.
    pub fn list_projects(&self) -> Vec<ProjectInfo> {
        let conn = self.conn();
        let mut stmt = match conn.prepare(
            "SELECT p.name, p.status, p.created_utc,
                    COUNT(DISTINCT a.name) as agent_count,
                    COUNT(DISTINCT CASE WHEN dl.status='pending' THEN dl.message_id END) as pending_count
             FROM projects p
             LEFT JOIN agents a ON a.project = p.name
             LEFT JOIN delivery_log dl ON dl.project = p.name
             GROUP BY p.name
             ORDER BY p.created_utc ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], |row| {
            Ok(ProjectInfo {
                name: row.get(0)?,
                status: row.get(1)?,
                created_utc: row.get(2)?,
                agent_count: row.get(3)?,
                pending_count: row.get(4)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Return statistics for a single project.
    pub fn project_stats(&self, project: &str) -> ProjectStats {
        let conn = self.conn();
        let agent_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM agents WHERE project = ?1")
            .ok()
            .and_then(|mut s| s.query_row(params![project], |r| r.get(0)).ok())
            .unwrap_or(0);
        let message_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM messages WHERE from_project = ?1")
            .ok()
            .and_then(|mut s| s.query_row(params![project], |r| r.get(0)).ok())
            .unwrap_or(0);
        let pending_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM delivery_log WHERE project = ?1 AND status = 'pending'")
            .ok()
            .and_then(|mut s| s.query_row(params![project], |r| r.get(0)).ok())
            .unwrap_or(0);
        ProjectStats { agent_count, message_count, pending_count }
    }

    /// Return broker-wide aggregate statistics.
    pub fn get_broker_stats(&self) -> BrokerStats {
        let conn = self.conn();
        let project_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM projects")
            .ok()
            .and_then(|mut s| s.query_row([], |r| r.get(0)).ok())
            .unwrap_or(0);
        let agent_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM agents")
            .ok()
            .and_then(|mut s| s.query_row([], |r| r.get(0)).ok())
            .unwrap_or(0);
        let pending_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM delivery_log WHERE status = 'pending'")
            .ok()
            .and_then(|mut s| s.query_row([], |r| r.get(0)).ok())
            .unwrap_or(0);
        BrokerStats { project_count, agent_count, pending_count }
    }

    /// Delete a project and all its associated data in a single transaction.
    /// Cascade order respects FK constraints: delivery_log → messages → subscriptions
    /// → channels → cross_project_allowed_sources → agents → projects.
    /// Returns Err if the project is not found.
    pub fn delete_project(&self, name: &str) -> Result<(), String> {
        // Check existence before opening a transaction — no transaction needed for a missing project.
        if !self.project_exists(name) {
            return Err(format!("Project '{}' not found", name));
        }

        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| format!("Failed to start transaction: {e}"))?;

        // Remove delivery_log rows referencing messages sent by this project,
        // plus delivery_log rows for agents within this project.
        tx.execute(
            "DELETE FROM delivery_log WHERE project = ?1
             OR message_id IN (SELECT id FROM messages WHERE from_project = ?1)",
            params![name],
        ).map_err(|e| format!("delete_project delivery_log: {e}"))?;

        tx.execute(
            "DELETE FROM subscriptions WHERE project = ?1",
            params![name],
        ).map_err(|e| format!("delete_project subscriptions: {e}"))?;

        tx.execute(
            "DELETE FROM messages WHERE from_project = ?1",
            params![name],
        ).map_err(|e| format!("delete_project messages: {e}"))?;

        tx.execute(
            "DELETE FROM channels WHERE project = ?1",
            params![name],
        ).map_err(|e| format!("delete_project channels: {e}"))?;

        tx.execute(
            "DELETE FROM cross_project_allowed_sources WHERE source_project = ?1 OR target_project = ?1",
            params![name],
        ).map_err(|e| format!("delete_project cross_project_allowed_sources: {e}"))?;

        tx.execute(
            "DELETE FROM agents WHERE project = ?1",
            params![name],
        ).map_err(|e| format!("delete_project agents: {e}"))?;

        let _ = tx.execute(
            "DELETE FROM projects WHERE name = ?1",
            params![name],
        ).map_err(|e| format!("delete_project projects: {e}"))?;

        tx.commit().map_err(|e| format!("delete_project commit: {e}"))?;
        Ok(())
    }

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

    /// Get the registered Ed25519 public key (hex) for an agent.
    /// Returns None if the agent is not found or has no public key registered.
    pub fn get_agent_public_key(&self, name: &str, project: &str) -> Option<String> {
        let conn = self.conn();
        conn.prepare("SELECT public_key FROM agents WHERE name = ?1 AND project = ?2")
            .ok()
            .and_then(|mut stmt| {
                stmt.query_row(params![name, project], |row| row.get::<_, Option<String>>(0))
                    .ok()
                    .flatten()
            })
    }

    /// Set (or replace) the registered Ed25519 public key (hex) for an agent.
    /// Returns Err if the agent is not found (0 rows affected).
    pub fn set_agent_public_key(&self, name: &str, project: &str, public_key_hex: &str) -> Result<(), String> {
        let rows = self.conn().execute(
            "UPDATE agents SET public_key = ?1 WHERE name = ?2 AND project = ?3",
            params![public_key_hex, name, project],
        ).map_err(|e| format!("Failed to set public key: {e}"))?;
        if rows == 0 {
            Err(format!("Agent '{}' not found in project '{}'", name, project))
        } else {
            Ok(())
        }
    }

    /// Find all (name, project) pairs with the given name across all projects.
    /// Returns empty Vec if no agent has this name. Used for implicit cross-project mention resolution.
    pub fn find_agents_by_name(&self, name: &str) -> Vec<(String, String)> {
        let conn = self.conn();
        let mut stmt = match conn.prepare("SELECT name, project FROM agents WHERE name = ?1") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![name], |row| Ok((row.get(0)?, row.get(1)?)))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default()
    }

    // --- Channels ---

    /// Ensure a channel exists within a project. Returns Err if the channel name is invalid.
    /// Valid channel names match `[\w-]+` — word characters and hyphens only.
    /// Dots are prohibited because '#channel.Project' is the cross-project addressing syntax.
    pub fn ensure_channel(&self, id: &str, project: &str) -> Result<(), String> {
        let valid = !id.is_empty()
            && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !valid {
            return Err(format!(
                "Channel name '{}' must only contain word characters and hyphens — \
                 dots are reserved for cross-project addressing (#channel.Project)",
                id
            ));
        }
        let _ = self.conn().execute(
            "INSERT OR IGNORE INTO channels (id, project) VALUES (?1, ?2)",
            params![id, project],
        );
        Ok(())
    }

    /// Check whether a channel exists in the given project.
    pub fn channel_exists(&self, channel_id: &str, project: &str) -> bool {
        let conn = self.conn();
        conn.prepare("SELECT 1 FROM channels WHERE id = ?1 AND project = ?2")
            .ok()
            .and_then(|mut stmt| stmt.query_row(params![channel_id, project], |_| Ok(())).ok())
            .is_some()
    }

    /// Seed the default cross-project allow entry ('*' → project) for a newly registered project.
    /// This permits any project to post to this project's channels by default.
    fn seed_cross_project_default(&self, project: &str) {
        let _ = self.conn().execute(
            "INSERT OR IGNORE INTO cross_project_allowed_sources (source_project, target_project) VALUES ('*', ?1)",
            params![project],
        );
    }

    /// Check whether source_project is allowed to post to target_project's channels.
    /// Returns true if a ('*', target_project) or (source_project, target_project) row exists.
    pub fn is_cross_project_allowed(&self, source_project: &str, target_project: &str) -> bool {
        let conn = self.conn();
        conn.prepare(
            "SELECT 1 FROM cross_project_allowed_sources \
             WHERE target_project = ?1 AND (source_project = ?2 OR source_project = '*') LIMIT 1"
        ).ok()
        .and_then(|mut stmt| stmt.query_row(params![target_project, source_project], |_| Ok(())).ok())
        .is_some()
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

    pub fn get_subscribers(&self, channel_id: &str, project: &str) -> Vec<(String, String)> {
        let conn = self.conn();
        let mut stmt = match conn.prepare(
            "SELECT agent_name, project FROM subscriptions WHERE channel_id = ?1 AND project = ?2",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map(params![channel_id, project], |row| {
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
        let mut conn = self.conn();
        let tx = match conn.transaction() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let messages: Vec<PendingMessage> = {
            let mut stmt = match tx.prepare(
                "SELECT m.id, m.from_agent, m.from_project, m.body, m.metadata, m.created_utc
                 FROM delivery_log dl
                 JOIN messages m ON dl.message_id = m.id
                 WHERE dl.agent_name = ?1 AND dl.project = ?2 AND dl.status = 'pending'
                 ORDER BY m.created_utc ASC",
            ) {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };
            match stmt.query_map(params![name, project], |row| {
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
            }
        };

        if !messages.is_empty() {
            let _ = tx.execute(
                "UPDATE delivery_log SET status = 'delivered', delivered_utc = datetime('now')
                 WHERE agent_name = ?1 AND project = ?2 AND status = 'pending'",
                params![name, project],
            );
        }

        let _ = tx.commit();
        messages
    }

    /// Peek at pending messages: returns count and list of senders without consuming.
    pub fn peek_pending(&self, name: &str, project: &str) -> Vec<(String, String, String)> {
        let conn = self.conn();
        let mut stmt = match conn.prepare(
            "SELECT m.from_agent, m.from_project, m.created_utc
             FROM delivery_log dl
             JOIN messages m ON dl.message_id = m.id
             WHERE dl.agent_name = ?1 AND dl.project = ?2 AND dl.status = 'pending'
             ORDER BY m.created_utc ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        match stmt.query_map(params![name, project], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        }) {
            Ok(r) => r.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn cleanup(&self, delivered_hours: u64, pending_hours: u64) -> (usize, usize) {
        let conn = self.conn();

        // Delete delivery_log entries BEFORE messages — foreign_keys=ON means deleting
        // a message while delivery_log still references it will fail with a constraint
        // error. Remove the referencing rows first, then the messages become deletable.

        // Step 1: Drop old delivered delivery_log entries.
        let _ = conn.execute(
            "DELETE FROM delivery_log
             WHERE status = 'delivered'
             AND delivered_utc < datetime('now', ?1)",
            params![format!("-{delivered_hours} hours")],
        );

        // Step 2: Delete messages that are no longer referenced by any delivery_log entry.
        // These are messages whose every delivery was completed and aged out in step 1.
        let delivered_deleted = conn.execute(
            "DELETE FROM messages
             WHERE id NOT IN (SELECT message_id FROM delivery_log)",
            [],
        ).unwrap_or(0);

        // Step 3: Drop expired pending delivery_log entries.
        let _ = conn.execute(
            "DELETE FROM delivery_log
             WHERE status = 'pending'
             AND message_id IN (
                 SELECT id FROM messages
                 WHERE created_utc < datetime('now', ?1)
             )",
            params![format!("-{pending_hours} hours")],
        );

        // Step 4: Delete messages that are now unreferenced and old enough.
        let pending_deleted = conn.execute(
            "DELETE FROM messages
             WHERE id NOT IN (SELECT message_id FROM delivery_log)
             AND created_utc < datetime('now', ?1)",
            params![format!("-{pending_hours} hours")],
        ).unwrap_or(0);

        (delivered_deleted, pending_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::ensure_schema;

    #[test]
    fn get_subscribers_isolated_by_project() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);

        repo.register_project("alpha", "key1").unwrap();
        repo.register_project("beta", "key2").unwrap();
        repo.register_agent("AgentA", "alpha", "").unwrap();
        repo.register_agent("AgentB", "beta", "").unwrap();

        // Both projects use a channel with the same logical name.
        // Each (channel_id, project) pair is an independent row — channels in different projects
        // with the same name do not collide. Both ensure_channel calls create their own row.
        // Subscriptions are still per (agent, project, channel_id).
        repo.ensure_channel("general", "alpha").unwrap();
        repo.ensure_channel("general", "beta").unwrap();
        repo.subscribe("AgentA", "alpha", "general");
        repo.subscribe("AgentB", "beta", "general");

        let alpha = repo.get_subscribers("general", "alpha");
        assert_eq!(alpha.len(), 1, "alpha should have exactly one subscriber");
        assert_eq!(alpha[0].0, "AgentA");

        let beta = repo.get_subscribers("general", "beta");
        assert_eq!(beta.len(), 1, "beta should have exactly one subscriber");
        assert_eq!(beta[0].0, "AgentB");
    }

    #[test]
    fn is_cross_project_allowed_wildcard_sentinel() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);

        repo.register_project("target", "key1").unwrap();
        // register_project seeds ('*', 'target') — any source should be allowed
        assert!(repo.is_cross_project_allowed("any-source", "target"),
            "wildcard sentinel should allow any source");
        assert!(repo.is_cross_project_allowed("another-source", "target"),
            "wildcard sentinel should allow multiple sources");
    }

    #[test]
    fn is_cross_project_allowed_explicit_pair() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        // Manually insert explicit pair (no wildcard) before handing conn to repo
        conn.execute(
            "INSERT INTO cross_project_allowed_sources VALUES ('ProjectA', 'ProjectB')",
            [],
        ).unwrap();
        let repo = Repository::new(conn);

        assert!(repo.is_cross_project_allowed("ProjectA", "ProjectB"),
            "explicit pair should be allowed");
        assert!(!repo.is_cross_project_allowed("ProjectC", "ProjectB"),
            "unlisted source should be denied when no wildcard");
    }

    #[test]
    fn is_cross_project_allowed_denied_no_rows() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        // No rows at all — any query should return false
        assert!(!repo.is_cross_project_allowed("any", "target"),
            "empty table should deny all");
    }

    #[test]
    fn channel_exists_returns_true_when_present() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "key").unwrap();
        repo.ensure_channel("mychan", "proj").unwrap();
        assert!(repo.channel_exists("mychan", "proj"));
        assert!(!repo.channel_exists("mychan", "other-proj"));
        assert!(!repo.channel_exists("other-chan", "proj"));
    }

    #[test]
    fn ensure_channel_rejects_dot_in_name() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "key").unwrap();
        let result = repo.ensure_channel("chan.name", "proj");
        assert!(result.is_err(), "dot in channel name must be rejected");
        assert!(result.unwrap_err().contains("must only contain"), "error message should describe constraint");
    }

    #[test]
    fn ensure_channel_accepts_hyphen_in_name() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "key").unwrap();
        assert!(repo.ensure_channel("my-channel", "proj").is_ok(),
            "hyphen in channel name must be accepted");
        assert!(repo.channel_exists("my-channel", "proj"));
    }

    #[test]
    fn find_agents_by_name_returns_empty_when_absent() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj-a", "key").unwrap();
        repo.register_agent("Alice", "proj-a", "").unwrap();
        let result = repo.find_agents_by_name("Bob");
        assert!(result.is_empty(), "unknown name should return empty Vec; got: {:?}", result);
    }

    #[test]
    fn find_agents_by_name_returns_single_when_unique() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj-a", "key").unwrap();
        repo.register_agent("Alice", "proj-a", "").unwrap();
        let result = repo.find_agents_by_name("Alice");
        assert_eq!(result, vec![("Alice".to_string(), "proj-a".to_string())],
            "unique name should return exactly one entry");
    }

    #[test]
    fn find_agents_by_name_returns_multiple_when_ambiguous() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj-a", "key1").unwrap();
        repo.register_project("proj-b", "key2").unwrap();
        repo.register_agent("Alice", "proj-a", "").unwrap();
        repo.register_agent("Alice", "proj-b", "").unwrap();
        let result = repo.find_agents_by_name("Alice");
        assert_eq!(result.len(), 2, "same name in two projects should return 2 entries; got: {:?}", result);
    }

    #[test]
    fn is_project_suspended_returns_false_for_active() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "key").unwrap();
        assert!(!repo.is_project_suspended("proj"), "newly registered project must not be suspended");
    }

    #[test]
    fn is_project_suspended_returns_true_after_suspend() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "key").unwrap();
        repo.set_project_status("proj", ProjectStatus::Suspended).unwrap();
        assert!(repo.is_project_suspended("proj"), "project must be suspended after set_project_status");
    }

    #[test]
    fn set_project_status_returns_err_for_unknown_project() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        let result = repo.set_project_status("nonexistent", ProjectStatus::Suspended);
        assert!(result.is_err(), "set_project_status on unknown project must return Err");
    }

    #[test]
    fn rotate_project_key_rejects_wrong_old_key() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "correct-key").unwrap();
        let result = repo.rotate_project_key("proj", "wrong-key", "new-key");
        assert!(result.is_err(), "rotate_project_key with wrong old key must return Err");
        assert!(result.unwrap_err().contains("Invalid current key"));
    }

    #[test]
    fn rotate_project_key_succeeds_and_invalidates_old_key() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "old-key").unwrap();
        repo.rotate_project_key("proj", "old-key", "new-key").unwrap();
        assert!(!repo.verify_project_key("proj", "old-key"), "old key must be rejected after rotation");
        assert!(repo.verify_project_key("proj", "new-key"), "new key must be accepted after rotation");
    }

    #[test]
    fn rotate_project_key_works_on_suspended_project() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "old-key").unwrap();
        repo.set_project_status("proj", ProjectStatus::Suspended).unwrap();
        // Suspended project must still allow key rotation
        let result = repo.rotate_project_key("proj", "old-key", "new-key");
        assert!(result.is_ok(), "key rotation must succeed on suspended project; got: {:?}", result);
    }

    #[test]
    fn delete_project_cascade_removes_all_rows() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        repo.register_project("proj", "key").unwrap();
        repo.register_agent("Alice", "proj", "").unwrap();
        repo.ensure_channel("general", "proj").unwrap();
        repo.subscribe("Alice", "proj", "general");

        repo.delete_project("proj").unwrap();

        assert!(!repo.project_exists("proj"), "project row must be deleted");
        assert!(!repo.agent_exists("Alice", "proj"), "agent row must be deleted");
        assert!(!repo.channel_exists("general", "proj"), "channel row must be deleted");
    }

    #[test]
    fn delete_project_returns_err_for_unknown_project() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let repo = Repository::new(conn);
        let result = repo.delete_project("nonexistent");
        assert!(result.is_err(), "delete_project on unknown project must return Err");
    }
}

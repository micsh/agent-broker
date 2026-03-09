use crate::broker::state::BrokerState;
use std::sync::Arc;

/// Handles store-and-forward delivery for offline agents.
pub struct DeliveryEngine {
    state: Arc<BrokerState>,
}

impl DeliveryEngine {
    pub fn new(state: Arc<BrokerState>) -> Self {
        Self { state }
    }

    /// Store a message in the database and attempt live delivery.
    /// Returns the message ID.
    pub async fn deliver(
        &self,
        id: &str,
        from_agent: &str,
        from_project: &str,
        to_agent: Option<&str>,
        to_channel: Option<&str>,
        body: &str,
        metadata: Option<&str>,
    ) -> Result<(), String> {
        // Persist the message
        {
            let conn = self.state.db.conn();
            conn.execute(
                "INSERT INTO messages (id, from_agent, from_project, to_agent, to_channel, body, metadata, created_utc)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'))",
                rusqlite::params![id, from_agent, from_project, to_agent, to_channel, body, metadata],
            ).map_err(|e| format!("Failed to persist message: {e}"))?;
        }

        // Direct agent delivery
        if let Some(target) = to_agent {
            // Try to find the agent in any project (or specific project if qualified)
            let (name, project) = if target.contains('.') {
                let parts: Vec<&str> = target.splitn(2, '.').collect();
                (parts[0].to_string(), parts[1].to_string())
            } else {
                // Find the agent in any project — prefer same project as sender
                let sessions = self.state.sessions.read().await;
                let found = sessions.values().find(|s| s.name == target);
                match found {
                    Some(s) => (s.name.clone(), s.project.clone()),
                    None => {
                        // Agent offline — record pending delivery
                        self.record_pending(id, target, from_project).await?;
                        return Ok(());
                    }
                }
            };

            let delivered = self.state.send_to_agent(&name, &project, body).await;
            if delivered {
                self.record_delivered(id, &name, &project).await?;
            } else {
                self.record_pending(id, &name, &project).await?;
            }
        }

        // Channel broadcast
        if let Some(channel) = to_channel {
            self.state
                .send_to_channel(channel, body, Some(from_agent))
                .await;
            // Record delivery for each subscriber (simplified — mark all as delivered for now)
        }

        Ok(())
    }

    /// Get pending messages for an agent that just came online.
    pub async fn drain_pending(&self, name: &str, project: &str) -> Vec<PendingMessage> {
        let conn = self.state.db.conn();
        let mut stmt = conn
            .prepare(
                "SELECT m.id, m.from_agent, m.from_project, m.body, m.metadata, m.created_utc
                 FROM delivery_log dl
                 JOIN messages m ON dl.message_id = m.id
                 WHERE dl.agent_name = ?1 AND dl.project = ?2 AND dl.status = 'pending'
                 ORDER BY m.created_utc ASC",
            )
            .unwrap();

        let messages: Vec<PendingMessage> = stmt
            .query_map(rusqlite::params![name, project], |row| {
                Ok(PendingMessage {
                    id: row.get(0)?,
                    from_agent: row.get(1)?,
                    from_project: row.get(2)?,
                    body: row.get(3)?,
                    metadata: row.get(4)?,
                    created_utc: row.get(5)?,
                })
            })
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        // Mark all as delivered
        if !messages.is_empty() {
            let _ = conn.execute(
                "UPDATE delivery_log SET status = 'delivered', delivered_utc = datetime('now')
                 WHERE agent_name = ?1 AND project = ?2 AND status = 'pending'",
                rusqlite::params![name, project],
            );
        }

        messages
    }

    async fn record_pending(&self, message_id: &str, agent: &str, project: &str) -> Result<(), String> {
        let conn = self.state.db.conn();
        conn.execute(
            "INSERT OR IGNORE INTO delivery_log (message_id, agent_name, project, status)
             VALUES (?1, ?2, ?3, 'pending')",
            rusqlite::params![message_id, agent, project],
        ).map_err(|e| format!("Failed to record pending: {e}"))?;
        Ok(())
    }

    async fn record_delivered(&self, message_id: &str, agent: &str, project: &str) -> Result<(), String> {
        let conn = self.state.db.conn();
        conn.execute(
            "INSERT OR REPLACE INTO delivery_log (message_id, agent_name, project, status, delivered_utc)
             VALUES (?1, ?2, ?3, 'delivered', datetime('now'))",
            rusqlite::params![message_id, agent, project],
        ).map_err(|e| format!("Failed to record delivery: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingMessage {
    pub id: String,
    pub from_agent: String,
    pub from_project: String,
    pub body: String,
    pub metadata: Option<String>,
    pub created_utc: String,
}

use crate::broker::state::BrokerState;
use crate::db::repository::PendingMessage;
use std::sync::Arc;

/// Manages pending-message draining for agents coming online and periodic TTL cleanup.
pub struct DeliveryEngine {
    state: Arc<BrokerState>,
}

impl DeliveryEngine {
    pub fn new(state: Arc<BrokerState>) -> Self {
        Self { state }
    }

    /// Get pending messages for an agent that just came online.
    /// Marks each returned row as `'sending'` — caller must call `mark_delivered` per
    /// message after each successful WS write to prevent silent loss on WS drops.
    pub fn drain_pending(&self, name: &str, project: &str) -> Vec<PendingMessage> {
        self.state.repo.drain_pending(name, project)
    }

    /// Store a DM DELIVER frame for offline delivery. Wraps `insert_message` +
    /// `record_pending` in sequence. Returns `Err` if the pending queue cap (1 000)
    /// is exceeded or on DB error.
    ///
    /// `to_name@to_project` — the recipient (offline agent).
    /// `from_agent@from_project` — the authenticated sender (for admin visibility).
    /// `frame_body` — the serialized DELIVER frame to deliver on reconnect.
    pub fn store_pending(
        &self,
        to_name: &str,
        to_project: &str,
        from_agent: &str,
        from_project: &str,
        frame_body: &str,
    ) -> Result<(), String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.state.repo.insert_message(&id, from_agent, from_project, to_name, to_project, frame_body)?;
        self.state.repo.record_pending(&id, to_name, to_project)?;
        Ok(())
    }

    /// Mark a single delivery row as `'delivered'` after the DELIVER frame was
    /// successfully written to the WS connection.
    pub fn mark_delivered(&self, message_id: &str, name: &str, project: &str) {
        self.state.repo.mark_delivered(message_id, name, project);
    }

    /// Run TTL cleanup. Called periodically.
    pub fn cleanup(&self, delivered_hours: u64, pending_hours: u64) -> (usize, usize) {
        self.state.repo.cleanup(delivered_hours, pending_hours)
    }
}

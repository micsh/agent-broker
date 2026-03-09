use crate::broker::state::BrokerState;
use crate::db::repository::PendingMessage;
use std::sync::Arc;

/// Handles store-and-forward delivery for offline agents.
pub struct DeliveryEngine {
    state: Arc<BrokerState>,
}

impl DeliveryEngine {
    pub fn new(state: Arc<BrokerState>) -> Self {
        Self { state }
    }

    /// Store a message and attempt live delivery.
    /// The broker enriches stanzas: `from` becomes fully qualified (name.project),
    /// and unqualified `to` scopes to the sender's project.
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
        // Enrich the from field to be fully qualified (name.project) if not already
        let expected_suffix = format!(".{}", from_project);
        let enriched = if from_agent.ends_with(&expected_suffix) {
            body.to_string()
        } else {
            let qualified_from = format!("{}.{}", from_agent, from_project);
            body.replace(
                &format!("from=\"{}\"", from_agent),
                &format!("from=\"{}\"", qualified_from),
            )
        };
        let body = enriched.as_str();

        self.state.repo.insert_message(id, from_agent, from_project, to_agent, to_channel, body, metadata)?;

        if let Some(target) = to_agent {
            let (name, project) = if target.contains('.') {
                // Cross-project: "David.AITeam.Platform"
                let parts: Vec<&str> = target.splitn(2, '.').collect();
                (parts[0].to_string(), parts[1].to_string())
            } else {
                // Unqualified name: scope to sender's project only
                (target.to_string(), from_project.to_string())
            };

            let delivered = self.state.send_to_agent(&name, &project, body).await;
            if delivered {
                self.state.repo.record_delivered(id, &name, &project)?;
            } else {
                self.state.repo.record_pending(id, &name, &project)?;
            }
        }

        if let Some(channel) = to_channel {
            self.state.send_to_channel(channel, body, Some(from_agent)).await;
        }

        Ok(())
    }

    /// Get pending messages for an agent that just came online.
    pub fn drain_pending(&self, name: &str, project: &str) -> Vec<PendingMessage> {
        self.state.repo.drain_pending(name, project)
    }

    /// Run TTL cleanup. Called periodically.
    pub fn cleanup(&self, delivered_hours: u64, pending_hours: u64) -> (usize, usize) {
        self.state.repo.cleanup(delivered_hours, pending_hours)
    }
}

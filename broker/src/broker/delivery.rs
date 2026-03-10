use crate::broker::state::BrokerState;
use crate::db::repository::PendingMessage;
use crate::stanza;
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
    /// `mentions` are agent names that should receive the message even if not subscribed to the channel.
    pub async fn deliver(
        &self,
        id: &str,
        from_agent: &str,
        from_project: &str,
        to_agent: Option<&str>,
        to_channel: Option<&str>,
        body: &str,
        metadata: Option<&str>,
        mentions: &[String],
    ) -> Result<(), String> {
        let enriched = stanza::enrich_from(body, from_agent, from_project);
        let body = enriched.as_str();

        self.state.repo.insert_message(id, from_agent, from_project, to_agent, to_channel, body, metadata)?;

        if let Some(target) = to_agent {
            let (name, project) = stanza::resolve_agent_name(target, from_project);
            self.deliver_to_agent(id, name, project, body).await?;
        }

        if let Some(channel) = to_channel {
            // Fan out to channel subscribers
            self.state.send_to_channel(channel, body, Some(from_agent)).await;

            // Deliver to mentioned agents not subscribed to this channel
            if !mentions.is_empty() {
                let subscribers: std::collections::HashSet<String> = self
                    .state
                    .repo
                    .get_subscribers(channel)
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();

                for mention in mentions {
                    if mention == from_agent || subscribers.contains(mention.as_str()) {
                        continue;
                    }
                    let (name, project) = stanza::resolve_agent_name(mention, from_project);

                    if !self.state.repo.agent_exists(name, project) {
                        continue;
                    }

                    self.deliver_to_agent(id, name, project, body).await?;
                }
            }
        }

        Ok(())
    }

    /// Attempt live delivery to a single agent, recording delivered or pending status.
    async fn deliver_to_agent(
        &self,
        message_id: &str,
        name: &str,
        project: &str,
        body: &str,
    ) -> Result<(), String> {
        if self.state.send_to_agent(name, project, body).await {
            self.state.repo.record_delivered(message_id, name, project)?;
        } else {
            self.state.repo.record_pending(message_id, name, project)?;
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

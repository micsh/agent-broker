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
                let parts: Vec<&str> = target.splitn(2, '.').collect();
                (parts[0].to_string(), parts[1].to_string())
            } else {
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
                    // Resolve mentioned agent: check sender's project first
                    let (name, project) = if mention.contains('.') {
                        let parts: Vec<&str> = mention.splitn(2, '.').collect();
                        (parts[0].to_string(), parts[1].to_string())
                    } else {
                        (mention.clone(), from_project.to_string())
                    };

                    if !self.state.repo.agent_exists(&name, &project) {
                        continue;
                    }

                    let delivered = self.state.send_to_agent(&name, &project, body).await;
                    if delivered {
                        let _ = self.state.repo.record_delivered(id, &name, &project);
                    } else {
                        let _ = self.state.repo.record_pending(id, &name, &project);
                    }
                }
            }
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

use crate::broker::state::BrokerState;
use crate::broker::DeliveryEngine;
use crate::stanza::{self, Destination, Stanza};
use std::sync::Arc;

/// Result of dispatching a stanza through the broker.
pub enum DispatchResult {
    /// Message was delivered. Contains the generated message ID.
    MessageSent(String),
    /// Presence was updated.
    PresenceUpdated,
}

/// Dispatch a parsed or raw stanza through the broker.
/// Handles both message delivery (with sender validation, destination resolution,
/// target validation) and presence updates.
///
/// `from_project` is the authenticated project of the sender.
/// `validate_target` controls whether target agent existence is checked (HTTP = yes, WS = no).
pub async fn dispatch_stanza(
    stanza: Stanza,
    from_project: &str,
    broker: &Arc<BrokerState>,
    delivery: &Arc<DeliveryEngine>,
    validate_target: bool,
) -> Result<DispatchResult, DispatchError> {
    match stanza {
        Stanza::Message(msg) => {
            let id = uuid::Uuid::new_v4().to_string();
            let (to_agent, to_channel) = match stanza::resolve_destination(&msg.to) {
                Destination::Agent(a) => (Some(a), None),
                Destination::Channel(c) => (None, Some(c)),
            };

            if validate_target {
                if let Some(ref agent) = to_agent {
                    let (name, target_project) = stanza::resolve_agent_name(agent, from_project);
                    if !broker.agent_exists(name, target_project) {
                        return Err(DispatchError::TargetNotFound {
                            agent: name.to_string(),
                            project: target_project.to_string(),
                        });
                    }
                }
            }

            delivery
                .deliver(
                    &id,
                    &msg.from,
                    from_project,
                    to_agent.as_deref(),
                    to_channel.as_deref(),
                    &msg.raw,
                    None,
                    &msg.mentions,
                )
                .await
                .map_err(DispatchError::DeliveryFailed)?;

            Ok(DispatchResult::MessageSent(id))
        }
        Stanza::Presence(p) => {
            broker.set_state(&p.from, from_project, p.status.into()).await;
            Ok(DispatchResult::PresenceUpdated)
        }
    }
}

/// Errors that can occur during stanza dispatch.
pub enum DispatchError {
    /// Target agent does not exist.
    TargetNotFound { agent: String, project: String },
    /// Delivery engine returned an error.
    DeliveryFailed(String),
}

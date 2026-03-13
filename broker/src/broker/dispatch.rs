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
/// Handles message delivery (sender validation, destination resolution, target validation)
/// and presence updates.
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
            match stanza::resolve_destination(&msg.to) {
                Destination::Agent(ref agent) => {
                    if validate_target {
                        let (name, target_project) = stanza::resolve_agent_name(agent, from_project);
                        if !broker.agent_exists(name, target_project) {
                            return Err(DispatchError::TargetNotFound {
                                agent: name.to_string(),
                                project: target_project.to_string(),
                            });
                        }
                    }
                    delivery
                        .deliver(&id, &msg.from, from_project, Some(agent), None, &msg.raw, None, &msg.mentions)
                        .await
                        .map_err(DispatchError::DeliveryFailed)?;
                }
                Destination::Channel(ref channel) => {
                    delivery
                        .deliver(&id, &msg.from, from_project, None, Some(channel), &msg.raw, None, &msg.mentions)
                        .await
                        .map_err(DispatchError::DeliveryFailed)?;
                }
                Destination::CrossProjectChannel { channel, project: target_project } => {
                    // Auth check — 403 if denied
                    if !broker.is_cross_project_allowed(from_project, &target_project) {
                        return Err(DispatchError::CrossProjectDenied {
                            source: from_project.to_string(),
                            target: target_project,
                        });
                    }
                    // Channel existence check — opaque 404 (does not distinguish project vs channel not found)
                    if !broker.channel_exists(&channel, &target_project) {
                        return Err(DispatchError::CrossProjectNotFound {
                            channel,
                            project: target_project,
                        });
                    }
                    delivery
                        .deliver_to_cross_project_channel(
                            &id, &msg.from, from_project, &channel, &target_project, &msg.raw, &msg.mentions,
                        )
                        .await
                        .map_err(DispatchError::DeliveryFailed)?;
                }
            }
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
    /// Cross-project channel post denied by the authorization table.
    CrossProjectDenied { source: String, target: String },
    /// Target channel or project does not exist.
    CrossProjectNotFound { channel: String, project: String },
}

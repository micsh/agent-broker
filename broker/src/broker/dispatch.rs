use crate::broker::state::BrokerState;
use crate::broker::DeliveryEngine;
use crate::db::repository::Repository;
use crate::stanza::{self, Destination, ResolvedMention, Stanza};
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
            let resolved_mentions = resolve_mentions(&msg.mentions, from_project, &broker.repo)?;
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
                        .deliver(&id, &msg.from, from_project, Some(agent), None, &msg.raw, None, &resolved_mentions)
                        .await
                        .map_err(DispatchError::DeliveryFailed)?;
                }
                Destination::Channel(ref channel) => {
                    delivery
                        .deliver(&id, &msg.from, from_project, None, Some(channel), &msg.raw, None, &resolved_mentions)
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
                            &id, &msg.from, from_project, &channel, &target_project, &msg.raw, &resolved_mentions,
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
#[derive(Debug)]
pub enum DispatchError {
    /// Target agent does not exist.
    TargetNotFound { agent: String, project: String },
    /// Delivery engine returned an error.
    DeliveryFailed(String),
    /// Cross-project channel post denied by the authorization table.
    CrossProjectDenied { source: String, target: String },
    /// Target channel or project does not exist.
    CrossProjectNotFound { channel: String, project: String },
    /// Bare mention name matches agents in 2+ projects — sender must qualify.
    AmbiguousMention { name: String, projects: Vec<String> },
}

/// Resolve each raw mention string to a ResolvedMention before delivery.
/// Algorithm (per ADR-004 D1):
///   Step 1: Contains '.' → already qualified. Split at first dot → name + project.
///           If project == from_project → SameProject, else CrossProject.
///   Step 2: Bare name, agent_exists(name, from_project) → SameProject.
///   Step 3: Bare name, NOT local, find_agents_by_name returns exactly 1 → CrossProject.
///   Step 4: Bare name, NOT local, find_agents_by_name returns 2+ → Err(AmbiguousMention).
///   Step 5: Bare name, NOT local, find_agents_by_name returns 0 → silent skip (not included in result).
/// If ANY mention triggers Step 4, returns Err immediately — no partial delivery.
fn resolve_mentions(
    mentions: &[String],
    from_project: &str,
    repo: &Repository,
) -> Result<Vec<ResolvedMention>, DispatchError> {
    let mut resolved = Vec::with_capacity(mentions.len());
    for mention in mentions {
        // Step 1: qualified (contains '.')
        if let Some(dot) = mention.find('.') {
            let name = mention[..dot].to_string();
            let project = mention[dot + 1..].to_string();
            if project == from_project {
                resolved.push(ResolvedMention::SameProject { name });
            } else {
                resolved.push(ResolvedMention::CrossProject { name, project });
            }
            continue;
        }
        // Step 2: bare name, local check
        if repo.agent_exists(mention, from_project) {
            resolved.push(ResolvedMention::SameProject { name: mention.clone() });
            continue;
        }
        // Step 3–5: global lookup
        let global = repo.find_agents_by_name(mention);
        match global.len() {
            0 => { /* Step 5: silent skip */ }
            1 => {
                // Step 3: unambiguous cross-project resolution
                let (name, project) = global.into_iter().next().unwrap();
                resolved.push(ResolvedMention::CrossProject { name, project });
            }
            _ => {
                // Step 4: ambiguous — fail-fast, no partial delivery
                let projects = global.into_iter().map(|(_, p)| p).collect();
                return Err(DispatchError::AmbiguousMention {
                    name: mention.clone(),
                    projects,
                });
            }
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn make_repo() -> Repository {
        db::open_memory().unwrap()
    }

    #[test]
    fn resolve_mentions_qualified_same_project() {
        let repo = make_repo();
        let mentions = vec!["Alice.proj-a".to_string()];
        let result = resolve_mentions(&mentions, "proj-a", &repo).unwrap();
        assert_eq!(result, vec![ResolvedMention::SameProject { name: "Alice".to_string() }]);
    }

    #[test]
    fn resolve_mentions_qualified_cross_project() {
        let repo = make_repo();
        let mentions = vec!["Alice.proj-b".to_string()];
        let result = resolve_mentions(&mentions, "proj-a", &repo).unwrap();
        assert_eq!(result, vec![ResolvedMention::CrossProject { name: "Alice".to_string(), project: "proj-b".to_string() }]);
    }

    #[test]
    fn resolve_mentions_bare_local_hit() {
        let repo = make_repo();
        repo.register_project("proj-a", "key").unwrap();
        repo.register_agent("Alice", "proj-a", "").unwrap();
        let mentions = vec!["Alice".to_string()];
        let result = resolve_mentions(&mentions, "proj-a", &repo).unwrap();
        assert_eq!(result, vec![ResolvedMention::SameProject { name: "Alice".to_string() }]);
    }

    #[test]
    fn resolve_mentions_bare_global_unique() {
        let repo = make_repo();
        repo.register_project("proj-a", "key1").unwrap();
        repo.register_project("proj-b", "key2").unwrap();
        repo.register_agent("Alice", "proj-b", "").unwrap();
        // Alice is NOT in proj-a, but exists uniquely in proj-b
        let mentions = vec!["Alice".to_string()];
        let result = resolve_mentions(&mentions, "proj-a", &repo).unwrap();
        assert_eq!(result, vec![ResolvedMention::CrossProject { name: "Alice".to_string(), project: "proj-b".to_string() }]);
    }

    #[test]
    fn resolve_mentions_bare_global_ambiguous() {
        let repo = make_repo();
        repo.register_project("proj-a", "key1").unwrap();
        repo.register_project("proj-b", "key2").unwrap();
        repo.register_project("proj-c", "key3").unwrap();
        repo.register_agent("Alice", "proj-a", "").unwrap();
        repo.register_agent("Alice", "proj-b", "").unwrap();
        let mentions = vec!["Alice".to_string()];
        let err = resolve_mentions(&mentions, "proj-c", &repo).unwrap_err();
        match err {
            DispatchError::AmbiguousMention { name, projects } => {
                assert_eq!(name, "Alice");
                assert_eq!(projects.len(), 2);
            }
            _ => panic!("expected AmbiguousMention"),
        }
    }

    #[test]
    fn resolve_mentions_bare_global_absent() {
        let repo = make_repo();
        repo.register_project("proj-a", "key").unwrap();
        let mentions = vec!["Ghost".to_string()];
        let result = resolve_mentions(&mentions, "proj-a", &repo).unwrap();
        assert!(result.is_empty(), "absent bare name should silently skip; got: {:?}", result);
    }

    #[test]
    fn resolve_mentions_ambiguous_aborts_all() {
        let repo = make_repo();
        repo.register_project("proj-a", "key1").unwrap();
        repo.register_project("proj-b", "key2").unwrap();
        repo.register_project("proj-c", "key3").unwrap();
        repo.register_agent("Known", "proj-a", "").unwrap();
        repo.register_agent("Ambiguous", "proj-a", "").unwrap();
        repo.register_agent("Ambiguous", "proj-b", "").unwrap();
        let mentions = vec!["Known".to_string(), "Ambiguous".to_string()];
        // Known resolves fine (local hit), Ambiguous triggers Step 4 → entire batch fails
        let result = resolve_mentions(&mentions, "proj-c", &repo);
        assert!(result.is_err(), "ambiguous mention must abort all resolution");
    }
}

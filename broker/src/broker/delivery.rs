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
            // Fan out to channel subscribers within the sender's project, recording delivery status
            let results = self.state.send_to_channel(channel, from_project, body, Some(from_agent)).await;
            for (sub_name, sub_project, delivered) in results {
                if delivered {
                    self.state.repo.record_delivered(id, &sub_name, &sub_project)?;
                } else {
                    self.state.repo.record_pending(id, &sub_name, &sub_project)?;
                }
            }

            // Deliver to mentioned agents not subscribed to this channel.
            // Auth table (cross_project_allowed_sources) gates cross-project mentions — default-allow ('*').
            if !mentions.is_empty() {
                let subscribers: std::collections::HashSet<(String, String)> = self
                    .state
                    .repo
                    .get_subscribers(channel, from_project)
                    .into_iter()
                    .collect();

                for mention in mentions {
                    // Normalize: 'David.agent-broker' → ('David', 'agent-broker')
                    let (mention_name, mention_project) = stanza::resolve_agent_name(mention, from_project);
                    // Skip if this is the sender (qualified check to avoid blocking cross-project agents
                    // with the same name) or already a channel subscriber
                    if (mention_name == from_agent && mention_project == from_project)
                        || subscribers.contains(&(mention_name.to_string(), mention_project.to_string()))
                    {
                        continue;
                    }
                    // T4: auth check for cross-project mentions — silently skip if denied
                    if mention_project != from_project
                        && !self.state.repo.is_cross_project_allowed(from_project, mention_project)
                    {
                        tracing::debug!(
                            "Cross-project mention to {}.{} denied by auth table",
                            mention_name, mention_project
                        );
                        continue;
                    }
                    if !self.state.repo.agent_exists(mention_name, mention_project) {
                        continue;
                    }
                    self.deliver_to_agent(id, mention_name, mention_project, body).await?;
                }
            }
        }

        Ok(())
    }

    /// Deliver a message to a channel in a different project.
    /// Enriches the stanza from= attribute, persists the message, and fans out to target subscribers.
    pub async fn deliver_to_cross_project_channel(
        &self,
        id: &str,
        from_agent: &str,
        from_project: &str,
        channel: &str,
        target_project: &str,
        body: &str,
    ) -> Result<(), String> {
        let enriched = stanza::enrich_from(body, from_agent, from_project);
        let body = enriched.as_str();

        self.state.repo.insert_message(id, from_agent, from_project, None, Some(channel), body, None)?;

        let results = self.state.send_to_channel(channel, target_project, body, None).await;
        for (sub_name, sub_project, delivered) in results {
            if delivered {
                self.state.repo.record_delivered(id, &sub_name, &sub_project)?;
            } else {
                self.state.repo.record_pending(id, &sub_name, &sub_project)?;
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
            tracing::warn!("No live WS session for {}.{} — message {} queued as pending", name, project, message_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::state::BrokerState;
    use crate::db;

    fn setup() -> (Arc<BrokerState>, DeliveryEngine) {
        let repo = Arc::new(db::open_memory().unwrap());
        let state = Arc::new(BrokerState::new(repo));
        let delivery = DeliveryEngine::new(state.clone());
        (state, delivery)
    }

    #[tokio::test]
    async fn channel_message_stored_as_pending_for_offline_subscriber() {
        let (state, delivery) = setup();

        // Register project and agents
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Sender", "proj", "").unwrap();
        state.repo.register_agent("Subscriber", "proj", "").unwrap();

        // Subscribe Subscriber to the channel (Subscriber is offline — no WS session)
        state.repo.ensure_channel("general", "proj").unwrap();
        state.repo.subscribe("Subscriber", "proj", "general");

        // Sender sends a channel message
        let body = r##"<message type="post" from="Sender" to="#general"><body>Hello</body></message>"##;
        delivery.deliver("msg-1", "Sender", "proj", None, Some("general"), body, None, &[]).await.unwrap();

        // Subscriber was offline — message must be stored as pending
        let pending = state.repo.drain_pending("Subscriber", "proj");
        assert_eq!(pending.len(), 1, "offline subscriber should have 1 pending message");
        assert_eq!(pending[0].id, "msg-1");
    }

    #[tokio::test]
    async fn channel_message_recorded_delivered_for_live_subscriber() {
        let (state, delivery) = setup();

        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Sender", "proj", "").unwrap();
        state.repo.register_agent("Receiver", "proj", "").unwrap();

        state.repo.ensure_channel("general", "proj").unwrap();
        state.repo.subscribe("Receiver", "proj", "general");

        // Connect Receiver so it has a live session (broadcast channel)
        let _rx = state.connect("Receiver", "proj").await;

        let body = r##"<message type="post" from="Sender" to="#general"><body>Hi</body></message>"##;
        delivery.deliver("msg-2", "Sender", "proj", None, Some("general"), body, None, &[]).await.unwrap();

        // Receiver was live — no pending messages should remain
        let pending = state.repo.drain_pending("Receiver", "proj");
        assert_eq!(pending.len(), 0, "live subscriber should have 0 pending messages");
    }

    // --- Body preservation: pending (store-and-forward) path ---

    #[tokio::test]
    async fn dm_plain_body_preserved_through_pending_drain() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        let body = r##"<message type="dm" from="Alice" to="Bob"><body>hello world</body></message>"##;
        delivery.deliver("m1", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let pending = state.repo.drain_pending("Bob", "proj");
        assert_eq!(pending.len(), 1);
        // Body content must be preserved verbatim (only from= is enriched)
        assert!(pending[0].body.contains("<body>hello world</body>"),
            "plain body not preserved; got: {}", pending[0].body);
    }

    #[tokio::test]
    async fn dm_xml_entities_in_body_preserved_through_pending_drain() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        // Body containing XML special characters — broker must not escape or transform them
        let body = r##"<message type="dm" from="Alice" to="Bob"><body>a &lt; b &gt; c &amp; d</body></message>"##;
        delivery.deliver("m2", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let pending = state.repo.drain_pending("Bob", "proj");
        assert_eq!(pending.len(), 1);
        assert!(pending[0].body.contains(r"a &lt; b &gt; c &amp; d"),
            "XML entities in body not preserved; got: {}", pending[0].body);
    }

    #[tokio::test]
    async fn dm_nested_xml_in_body_preserved_through_pending_drain() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        // Body containing nested XML fragment — opaque to broker, must pass through unchanged
        let body = r##"<message type="dm" from="Alice" to="Bob"><body><thread id="t-123" /><inner>nested content</inner></body></message>"##;
        delivery.deliver("m3", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let pending = state.repo.drain_pending("Bob", "proj");
        assert_eq!(pending.len(), 1);
        assert!(pending[0].body.contains(r#"<thread id="t-123" /><inner>nested content</inner>"#),
            "nested XML in body not preserved; got: {}", pending[0].body);
    }

    #[tokio::test]
    async fn dm_empty_body_element_preserved_through_pending_drain() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        // A stanza with an empty <body></body> — broker must accept and preserve as-is
        let body = r##"<message type="dm" from="Alice" to="Bob"><body></body></message>"##;
        delivery.deliver("m4", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let pending = state.repo.drain_pending("Bob", "proj");
        assert_eq!(pending.len(), 1);
        assert!(pending[0].body.contains("<body></body>"),
            "empty body element not preserved; got: {}", pending[0].body);
    }

    #[tokio::test]
    async fn dm_no_body_element_preserved_through_pending_drain() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        // A stanza with no body element at all — broker must accept and deliver unchanged
        let body = r##"<message type="dm" from="Alice" to="Bob"></message>"##;
        delivery.deliver("m5", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let pending = state.repo.drain_pending("Bob", "proj");
        assert_eq!(pending.len(), 1);
        assert!(pending[0].body.contains("</message>"),
            "no-body stanza not preserved; got: {}", pending[0].body);
        // Body content section must be empty (no body element injected)
        assert!(!pending[0].body.contains("<body>"),
            "broker must not inject a <body> element; got: {}", pending[0].body);
    }

    #[tokio::test]
    async fn enrich_from_does_not_touch_body_content() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        // Body text contains from="Alice" — must NOT be rewritten by enrich_from
        let body = r##"<message type="dm" from="Alice" to="Bob"><body>Sent from="Alice" directly.</body></message>"##;
        delivery.deliver("m6", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let pending = state.repo.drain_pending("Bob", "proj");
        assert_eq!(pending.len(), 1);
        // Opening tag: from= must be qualified
        assert!(pending[0].body.starts_with(r#"<message type="dm" from="Alice.proj""#),
            "opening tag from= not enriched; got: {}", pending[0].body);
        // Body text with from="Alice" must NOT be rewritten
        assert!(pending[0].body.contains(r#"from="Alice" directly"#),
            "enrich_from rewrote body content (must not); got: {}", pending[0].body);
    }

    // --- Body preservation: live delivery (WS broadcast) path ---

    #[tokio::test]
    async fn dm_plain_body_preserved_via_live_delivery() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        // Bob connects live
        let mut rx = state.connect("Bob", "proj").await;

        let body = r##"<message type="dm" from="Alice" to="Bob"><body>live hello</body></message>"##;
        delivery.deliver("m7", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        // Bob receives message via broadcast channel (live WS path)
        let received = rx.recv().await.expect("should receive live message");
        assert!(received.contains("<body>live hello</body>"),
            "plain body not preserved on live delivery; got: {received}");
    }

    #[tokio::test]
    async fn dm_xml_entities_preserved_via_live_delivery() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        let mut rx = state.connect("Bob", "proj").await;

        let body = r##"<message type="dm" from="Alice" to="Bob"><body>x &lt; y &gt; z</body></message>"##;
        delivery.deliver("m8", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let received = rx.recv().await.expect("should receive live message");
        assert!(received.contains(r"x &lt; y &gt; z"),
            "XML entities not preserved on live delivery; got: {received}");
    }

    #[tokio::test]
    async fn dm_nested_xml_preserved_via_live_delivery() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Alice", "proj", "").unwrap();
        state.repo.register_agent("Bob", "proj", "").unwrap();

        let mut rx = state.connect("Bob", "proj").await;

        let body = r##"<message type="dm" from="Alice" to="Bob"><body><ref post-id="p-abc" /></body></message>"##;
        delivery.deliver("m9", "Alice", "proj", Some("Bob"), None, body, None, &[]).await.unwrap();

        let received = rx.recv().await.expect("should receive live message");
        assert!(received.contains(r#"<ref post-id="p-abc" />"#),
            "nested XML not preserved on live delivery; got: {received}");
    }

    #[tokio::test]
    async fn channel_message_with_no_subscribers_does_not_error() {
        let (state, delivery) = setup();
        state.repo.register_project("proj", "key").unwrap();
        state.repo.register_agent("Sender", "proj", "").unwrap();
        state.repo.ensure_channel("empty-channel", "proj").unwrap();
        // No subscriptions added

        let body = r##"<message type="post" from="Sender" to="#empty-channel"><body>hi</body></message>"##;
        let result = delivery.deliver("msg-zero", "Sender", "proj", None, Some("empty-channel"), body, None, &[]).await;
        assert!(result.is_ok(), "delivery to channel with no subscribers must not error");
    }
}

use serde::{Deserialize, Serialize};

/// A parsed stanza. The broker only extracts routing headers —
/// the full original XML is preserved as `raw` for forwarding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stanza {
    Message(MessageStanza),
    Presence(PresenceStanza),
}

/// Only the fields the broker needs for routing. Body, subject, thread,
/// post-type etc. are application concerns — forwarded as raw XML.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageStanza {
    pub from: String,
    pub to: String,
    pub message_type: MessageType,
    /// Comma-separated agent names from the `mentions` attribute, if present.
    pub mentions: Vec<String>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceStanza {
    pub from: String,
    pub status: PresenceStatus,
    pub raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Post,
    Reply,
    #[serde(rename = "dm")]
    DirectMessage,
    Reaction,
}

impl MessageType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "post" => Some(Self::Post),
            "reply" => Some(Self::Reply),
            "dm" => Some(Self::DirectMessage),
            "reaction" => Some(Self::Reaction),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceStatus {
    Available,
    Busy,
    Offline,
}

impl PresenceStatus {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "available" => Some(Self::Available),
            "busy" => Some(Self::Busy),
            "offline" => Some(Self::Offline),
            _ => None,
        }
    }
}

/// Routing destination extracted from the stanza `to` field.
#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    /// Direct message to an agent. May be "Name" or "Name.Project".
    Agent(String),
    /// Broadcast to a channel within the sender's project (the '#' prefix is stripped).
    Channel(String),
    /// Cross-project channel post: '#channel.Project' — channel in a different project.
    CrossProjectChannel { channel: String, project: String },
}

/// A resolved mention — name and project are already determined before delivery.
/// SameProject: bare name found in from_project (or a qualified same-project mention).
/// CrossProject: bare name resolved globally to exactly one other project, or explicitly qualified.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedMention {
    SameProject { name: String },
    CrossProject { name: String, project: String },
}

/// Interpret the `to` attribute: '#channel' → Channel, '#channel.Project' → CrossProjectChannel,
/// otherwise → Agent.
pub fn resolve_destination(to: &str) -> Destination {
    if to.starts_with('#') {
        let s = &to[1..];
        if let Some(dot) = s.find('.') {
            Destination::CrossProjectChannel {
                channel: s[..dot].to_string(),
                project: s[dot + 1..].to_string(),
            }
        } else {
            Destination::Channel(s.to_string())
        }
    } else {
        Destination::Agent(to.to_string())
    }
}

/// Resolve an agent target (e.g. "Zoe" or "Zoe.OtherProject") into (name, project).
/// If the target contains a dot, it's split as name.project.
/// Otherwise, defaults to the sender's project.
pub fn resolve_agent_name<'a>(target: &'a str, default_project: &'a str) -> (&'a str, &'a str) {
    if let Some(dot) = target.find('.') {
        (&target[..dot], &target[dot + 1..])
    } else {
        (target, default_project)
    }
}

/// Qualify the `to` attribute in raw stanza XML for a remote recipient.
/// Turns `to="#general"` into `to="#general.from_project"` in the opening tag only.
/// If already qualified (the channel address contains a '.'), returns unchanged.
/// Body content is never rewritten.
pub fn enrich_to_for_remote(body: &str, channel: &str, from_project: &str) -> String {
    let unqualified = format!("to=\"#{}\"", channel);
    let qualified = format!("to=\"#{}.{}\"", channel, from_project);
    let tag_end = body.find('>').unwrap_or(body.len());
    let (opening, rest) = body.split_at(tag_end);
    // Already qualified: to="#channel." present (any project suffix)
    if opening.contains(&format!("to=\"#{channel}.")) || !opening.contains(&unqualified) {
        return body.to_string();
    }
    format!("{}{}", opening.replacen(&unqualified, &qualified, 1), rest)
}


/// Qualify the `from` attribute in raw stanza XML to fully-qualified form (name.project).
/// If already qualified, returns the body unchanged.
/// Replacement is scoped to the opening tag only — body content is never rewritten.
pub fn enrich_from(body: &str, from_agent: &str, from_project: &str) -> String {
    let expected_suffix = format!(".{}", from_project);
    if from_agent.ends_with(&expected_suffix) {
        return body.to_string();
    }
    let qualified = format!("{}.{}", from_agent, from_project);
    let tag_end = body.find('>').unwrap_or(body.len());
    let (opening, rest) = body.split_at(tag_end);
    let fixed = opening.replace(
        &format!("from=\"{}\"", from_agent),
        &format!("from=\"{}\"", qualified),
    );
    format!("{}{}", fixed, rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrich_from_qualifies_unqualified_agent() {
        let xml = r##"<message type="post" from="Zoe" to="#impl"><body>Done.</body></message>"##;
        let result = enrich_from(xml, "Zoe", "myproject");
        assert!(result.contains(r#"from="Zoe.myproject""#));
    }

    #[test]
    fn enrich_from_already_qualified_returns_unchanged() {
        let xml = r##"<message type="post" from="Maya.proj" to="#analysis"><body>Hello</body></message>"##;
        let result = enrich_from(xml, "Maya.proj", "proj");
        assert_eq!(result, xml);
    }

    #[test]
    fn enrich_from_does_not_rewrite_body_content() {
        // The body text contains from="Maya" — only the opening tag attribute must be updated.
        let xml = r##"<message type="post" from="Maya" to="#analysis"><body>Sent from="Maya" directly.</body></message>"##;
        let enriched = enrich_from(xml, "Maya", "proj");
        // Opening tag should have the qualified name
        assert!(enriched.starts_with(r#"<message type="post" from="Maya.proj""#));
        // Body content must be preserved verbatim
        assert!(
            enriched.contains(r#"from="Maya""#),
            "Body text with from=\"Maya\" must not be rewritten; got: {enriched}"
        );
    }

    #[test]
    fn resolve_cross_project_channel() {
        assert_eq!(
            resolve_destination("#general.AITeam.Platform"),
            Destination::CrossProjectChannel {
                channel: "general".to_string(),
                project: "AITeam.Platform".to_string(),
            }
        );
    }

    #[test]
    fn resolve_same_project_channel_unchanged() {
        assert_eq!(resolve_destination("#planning"), Destination::Channel("planning".to_string()));
    }

    #[test]
    fn resolve_agent_unchanged() {
        assert_eq!(resolve_destination("Victoria"), Destination::Agent("Victoria".to_string()));
    }

    #[test]
    fn resolve_cross_project_channel_first_dot_split() {
        // '#general.notes' — first dot splits at 'notes', even when project name has no dot
        assert_eq!(
            resolve_destination("#general.notes"),
            Destination::CrossProjectChannel {
                channel: "general".to_string(),
                project: "notes".to_string(),
            }
        );
    }

    // --- T2: from= normalisation via resolve_agent_name ---

    #[test]
    fn resolve_agent_name_bare_name_passes() {
        // "Victoria" authenticated as "Victoria" in "my-project" — bare name accepted
        let (name, _) = resolve_agent_name("Victoria", "my-project");
        assert_eq!(name, "Victoria");
    }

    #[test]
    fn resolve_agent_name_qualified_same_project_passes() {
        // "Victoria.my-project" — qualified form, same project → name extracted correctly
        let (name, project) = resolve_agent_name("Victoria.my-project", "my-project");
        assert_eq!(name, "Victoria");
        assert_eq!(project, "my-project");
    }

    #[test]
    fn resolve_agent_name_different_agent_detected() {
        // "OtherAgent" authenticated as "Victoria" — name mismatch detectable
        let (name, _) = resolve_agent_name("OtherAgent", "my-project");
        assert_ne!(name, "Victoria");
    }

    // --- enrich_to_for_remote ---

    #[test]
    fn enrich_to_qualifies_unqualified_channel() {
        let xml = r##"<message type="post" from="Alice.proj" to="#general"><body>Hi</body></message>"##;
        let result = enrich_to_for_remote(xml, "general", "myproject");
        assert!(result.contains(r###"to="#general.myproject""###),
            "expected qualified to=; got: {result}");
        assert!(!result.contains(r##"to="#general" "##) && !result.contains(r##"to="#general">"##),
            "unqualified to= must be replaced; got: {result}");
        assert!(result.contains("<body>Hi</body>"), "body not preserved; got: {result}");
    }

    #[test]
    fn enrich_to_already_qualified_returns_unchanged() {
        let xml = r##"<message type="post" from="Alice.proj" to="#general.other"><body>Hi</body></message>"##;
        let result = enrich_to_for_remote(xml, "general", "myproject");
        assert_eq!(result, xml, "already-qualified to= must not be changed");
    }

    #[test]
    fn enrich_to_does_not_rewrite_body_content() {
        let xml = r##"<message type="post" from="Alice.proj" to="#general"><body>reply to this channel</body></message>"##;
        let result = enrich_to_for_remote(xml, "general", "myproject");
        // Opening tag must be qualified
        assert!(result.contains(r###"to="#general.myproject""###),
            "opening tag not qualified; got: {result}");
        // Body must be preserved verbatim
        assert!(result.contains("<body>reply to this channel</body>"),
            "body content must not be changed; got: {result}");
    }
}

/// Error returned when a stanza cannot be parsed.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    /// Input doesn't start with a known stanza tag.
    NotAStanza,
    /// Missing a required attribute.
    MissingAttribute(String),
    /// Attribute value is not a recognized enum variant.
    InvalidValue { attribute: String, value: String },
    /// The stanza XML is structurally broken.
    Malformed(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::NotAStanza => write!(f, "Input is not a stanza (must start with <message or <presence)"),
            ParseError::MissingAttribute(attr) => write!(f, "Missing required attribute: {attr}"),
            ParseError::InvalidValue { attribute, value } => {
                write!(f, "Invalid value for '{attribute}': '{value}'")
            }
            ParseError::Malformed(msg) => write!(f, "Malformed stanza: {msg}"),
        }
    }
}

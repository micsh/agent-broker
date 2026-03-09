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
/// mentions, post-type etc. are application concerns — forwarded as raw XML.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageStanza {
    pub from: String,
    pub to: String,
    pub message_type: MessageType,
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
    /// Broadcast to a channel (the '#' prefix is stripped).
    Channel(String),
}

/// Interpret the `to` attribute: '#channel' → channel, otherwise → agent.
pub fn resolve_destination(to: &str) -> Destination {
    if to.starts_with('#') {
        Destination::Channel(to[1..].to_string())
    } else {
        Destination::Agent(to.to_string())
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

use regex::Regex;
use std::sync::LazyLock;
use super::types::*;

static ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w[\w-]*)="([^"]*)""#).unwrap()
});

/// Parse a single stanza. Extracts only routing headers (from, to, type/status).
/// The full XML is preserved as `raw` for forwarding to recipients.
pub fn parse(text: &str) -> Result<Stanza, ParseError> {
    let trimmed = text.trim();
    if trimmed.starts_with("<message") {
        if !trimmed.ends_with("</message>") && !trimmed.ends_with("/>") {
            return Err(ParseError::Malformed("Missing closing </message> tag".into()));
        }
        parse_message(trimmed, text).map(Stanza::Message)
    } else if trimmed.starts_with("<presence") {
        if !trimmed.ends_with("</presence>") && !trimmed.ends_with("/>") {
            return Err(ParseError::Malformed("Missing closing </presence> tag".into()));
        }
        parse_presence(trimmed, text).map(Stanza::Presence)
    } else {
        Err(ParseError::NotAStanza)
    }
}

fn parse_message(xml: &str, raw: &str) -> Result<MessageStanza, ParseError> {
    let tag_end = xml.find('>').ok_or(ParseError::Malformed("No closing > on opening tag".into()))?;
    let attrs = parse_attrs(&xml[..tag_end]);

    let from = require_attr(&attrs, "from")?;
    let to = require_attr(&attrs, "to")?;
    let type_str = require_attr(&attrs, "type")?;
    let message_type = MessageType::from_str(&type_str).ok_or_else(|| ParseError::InvalidValue {
        attribute: "type".into(),
        value: type_str,
    })?;

    Ok(MessageStanza {
        from,
        to,
        message_type,
        raw: raw.to_string(),
    })
}

fn parse_presence(xml: &str, raw: &str) -> Result<PresenceStanza, ParseError> {
    let tag_end = xml.find('>').ok_or(ParseError::Malformed("No closing > on opening tag".into()))?;
    let attrs = parse_attrs(&xml[..tag_end]);

    let from = require_attr(&attrs, "from")?;
    let status_str = require_attr(&attrs, "status")?;
    let status = PresenceStatus::from_str(&status_str).ok_or_else(|| ParseError::InvalidValue {
        attribute: "status".into(),
        value: status_str,
    })?;

    Ok(PresenceStanza {
        from,
        status,
        raw: raw.to_string(),
    })
}

fn require_attr(
    attrs: &std::collections::HashMap<String, String>,
    name: &str,
) -> Result<String, ParseError> {
    attrs
        .get(name)
        .cloned()
        .ok_or_else(|| ParseError::MissingAttribute(name.into()))
}

fn parse_attrs(tag: &str) -> std::collections::HashMap<String, String> {
    ATTR_RE
        .captures_iter(tag)
        .map(|cap| (cap[1].to_string(), cap[2].to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Routing extraction ---

    #[test]
    fn parse_message_extracts_routing() {
        let xml = r##"<message type="post" from="Maya" to="#analysis" post-type="finding">
  <thread id="new" />
  <subject>Null Reference Issue</subject>
  <body>@Architect fix this.</body>
</message>"##;

        match parse(xml).unwrap() {
            Stanza::Message(m) => {
                assert_eq!(m.from, "Maya");
                assert_eq!(m.to, "#analysis");
                assert_eq!(m.message_type, MessageType::Post);
                assert_eq!(m.raw, xml);
            }
            _ => panic!("Expected Message"),
        }
    }

    #[test]
    fn parse_reply() {
        let xml = r##"<message type="reply" from="Zoe" to="#analysis">
  <thread id="t-42" />
  <body>Fixed.</body>
</message>"##;

        match parse(xml).unwrap() {
            Stanza::Message(m) => {
                assert_eq!(m.message_type, MessageType::Reply);
                assert_eq!(m.raw, xml);
            }
            _ => panic!("Expected Message"),
        }
    }

    #[test]
    fn parse_dm() {
        let xml = r##"<message type="dm" from="Sarah" to="Zoe">
  <thread id="new" />
  <body>How's auth going?</body>
</message>"##;

        match parse(xml).unwrap() {
            Stanza::Message(m) => {
                assert_eq!(m.message_type, MessageType::DirectMessage);
                assert_eq!(m.to, "Zoe");
            }
            _ => panic!("Expected Message"),
        }
    }

    #[test]
    fn parse_reaction() {
        let xml = r##"<message type="reaction" from="Maya" to="#analysis">
  <thread id="t-abc123" />
  <body>👍</body>
  <ref post-id="p-xyz789" />
</message>"##;

        match parse(xml).unwrap() {
            Stanza::Message(m) => assert_eq!(m.message_type, MessageType::Reaction),
            _ => panic!("Expected Message"),
        }
    }

    #[test]
    fn parse_presence() {
        let xml = r##"<presence from="Maya" status="available">
  <subscribe tag="#analysis" />
</presence>"##;

        match parse(xml).unwrap() {
            Stanza::Presence(p) => {
                assert_eq!(p.from, "Maya");
                assert_eq!(p.status, PresenceStatus::Available);
                assert_eq!(p.raw, xml);
            }
            _ => panic!("Expected Presence"),
        }
    }

    #[test]
    fn parse_self_closing_presence() {
        let xml = r#"<presence from="Sarah" status="busy" />"#;
        match parse(xml).unwrap() {
            Stanza::Presence(p) => assert_eq!(p.status, PresenceStatus::Busy),
            _ => panic!("Expected Presence"),
        }
    }

    // --- Raw preservation ---

    #[test]
    fn raw_preserves_original_including_whitespace() {
        let xml = "  <presence from=\"Sarah\" status=\"available\" />  ";
        match parse(xml).unwrap() {
            Stanza::Presence(p) => assert_eq!(p.raw, xml),
            _ => panic!("Expected Presence"),
        }
    }

    // --- Malformed body content (broker doesn't care, it's opaque) ---

    #[test]
    fn body_with_html_tags() {
        let xml = r##"<message type="post" from="Zoe" to="#implementation">
  <body>Replace <link rel="stylesheet" href="foo.css"> with local.</body>
</message>"##;
        assert!(parse(xml).is_ok());
    }

    #[test]
    fn body_with_incomplete_tags() {
        let xml = r##"<message type="post" from="Maya" to="#analysis">
  <body>Found unclosed <div and <span class= in the template.</body>
</message>"##;
        assert!(parse(xml).is_ok());
    }

    #[test]
    fn body_with_angle_brackets() {
        let xml = r##"<message type="post" from="Maya" to="#analysis">
  <body>Check if a < b > c and x > 0.</body>
</message>"##;
        assert!(parse(xml).is_ok());
    }

    #[test]
    fn body_with_code_snippet() {
        let xml = r##"<message type="post" from="Zoe" to="#implementation">
  <body>Use <Router><Route path="/home" /></Router> in App.razor.</body>
</message>"##;
        assert!(parse(xml).is_ok());
    }

    #[test]
    fn body_with_xml_declaration() {
        let xml = r##"<message type="post" from="Maya" to="#analysis">
  <body>File starts with <?xml version="1.0"?> which is wrong.</body>
</message>"##;
        assert!(parse(xml).is_ok());
    }

    // --- Error cases ---

    #[test]
    fn not_a_stanza() {
        assert_eq!(parse("Hello world").unwrap_err(), ParseError::NotAStanza);
        assert_eq!(parse("<div>nope</div>").unwrap_err(), ParseError::NotAStanza);
    }

    #[test]
    fn missing_required_attributes() {
        let xml = r##"<message from="Maya" to="#analysis">
  <body>No type.</body>
</message>"##;
        assert!(matches!(parse(xml).unwrap_err(), ParseError::MissingAttribute(a) if a == "type"));

        let xml = r##"<message type="post" to="#analysis">
  <body>No from.</body>
</message>"##;
        assert!(matches!(parse(xml).unwrap_err(), ParseError::MissingAttribute(a) if a == "from"));

        let xml = r#"<presence from="Maya" />"#;
        assert!(matches!(parse(xml).unwrap_err(), ParseError::MissingAttribute(a) if a == "status"));
    }

    #[test]
    fn invalid_type_value() {
        let xml = r##"<message type="yell" from="Maya" to="#analysis">
  <body>Bad type.</body>
</message>"##;
        assert!(matches!(
            parse(xml).unwrap_err(),
            ParseError::InvalidValue { attribute, value } if attribute == "type" && value == "yell"
        ));
    }

    #[test]
    fn invalid_status_value() {
        let xml = r#"<presence from="Maya" status="sleeping" />"#;
        assert!(matches!(
            parse(xml).unwrap_err(),
            ParseError::InvalidValue { attribute, value } if attribute == "status" && value == "sleeping"
        ));
    }

    #[test]
    fn unclosed_message_tag() {
        let xml = r##"<message type="post" from="Maya" to="#analysis">
  <body>No closing tag."##;
        assert!(matches!(parse(xml).unwrap_err(), ParseError::Malformed(_)));
    }

    #[test]
    fn empty_input() {
        assert_eq!(parse("").unwrap_err(), ParseError::NotAStanza);
        assert_eq!(parse("   ").unwrap_err(), ParseError::NotAStanza);
    }

    // --- Destination resolution ---

    #[test]
    fn resolve_channel() {
        assert_eq!(
            super::super::types::resolve_destination("#analysis"),
            super::super::types::Destination::Channel("analysis".to_string())
        );
    }

    #[test]
    fn resolve_agent() {
        assert_eq!(
            super::super::types::resolve_destination("Zoe"),
            super::super::types::Destination::Agent("Zoe".to_string())
        );
    }

    #[test]
    fn resolve_agent_with_project() {
        assert_eq!(
            super::super::types::resolve_destination("Zoe.AITeam"),
            super::super::types::Destination::Agent("Zoe.AITeam".to_string())
        );
    }
}

//! HttpFrame — HTTP-shaped text framing for WebSocket transport (spec §1).
//!
//! One frame per WS `Message::Text`. Frames are never split across messages.
//! `Content-Length` is mandatory on every frame; body is exactly that many bytes.
//! Body may contain CR, LF, or CRLF — readers consume exactly Content-Length bytes.
//!
//! # Wire format
//! ```text
//! VERB /path HTTP/1.1\r\n          ← request frame
//! HTTP/1.1 NNN Reason\r\n          ← response frame
//! Header-Name: value\r\n
//! Content-Length: N\r\n
//! \r\n
//! <body of exactly N bytes>
//! ```

// ── Types ─────────────────────────────────────────────────────────────────────

/// The opening line of a frame — request or response shape.
#[derive(Debug, Clone, PartialEq)]
pub enum FirstLine {
    Request { verb: String, path: String },
    Response { status: u16, reason: String },
}

/// A parsed HttpFrame. Either a request (verb + path) or a response (status + reason).
#[derive(Debug, Clone, PartialEq)]
pub struct HttpFrame {
    pub first_line: FirstLine,
    /// Headers as ordered (name, value) pairs. Names are case-preserved; lookup is case-insensitive.
    pub headers: Vec<(String, String)>,
    /// Frame body. UTF-8 text. Byte length must equal Content-Length header value.
    pub body: String,
}

/// Errors returned when an HttpFrame cannot be parsed.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    EmptyFrame,
    MissingHeaderTerminator,
    InvalidFirstLine(String),
    HeaderMalformed(String),
    MissingContentLength,
    BadContentLength(String),
    BodyTooShort { expected: usize, got: usize },
    BodyNotUtf8,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::EmptyFrame => write!(f, "Frame is empty"),
            ParseError::MissingHeaderTerminator => write!(f, "Missing \\r\\n\\r\\n header terminator"),
            ParseError::InvalidFirstLine(s) => write!(f, "Invalid first line: '{s}'"),
            ParseError::HeaderMalformed(s) => write!(f, "Malformed header line: '{s}'"),
            ParseError::MissingContentLength => write!(f, "Missing mandatory Content-Length header"),
            ParseError::BadContentLength(s) => write!(f, "Content-Length is not a valid integer: '{s}'"),
            ParseError::BodyTooShort { expected, got } => {
                write!(f, "Body too short: Content-Length={expected}, got {got} bytes")
            }
            ParseError::BodyNotUtf8 => write!(f, "Body bytes are not valid UTF-8"),
        }
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a single HttpFrame from a WS text message string.
///
/// # Spec §1 compliance
/// - Content-Length is mandatory.
/// - Body is consumed as exactly Content-Length bytes.
/// - Body may contain CRLF; the byte slice is converted to UTF-8.
pub fn parse(text: &str) -> Result<HttpFrame, ParseError> {
    if text.is_empty() {
        return Err(ParseError::EmptyFrame);
    }

    // Locate the header/body boundary: \r\n\r\n
    let header_end = text.find("\r\n\r\n")
        .ok_or(ParseError::MissingHeaderTerminator)?;

    let header_section = &text[..header_end];
    let body_start = header_end + 4; // skip the 4-byte terminator

    let mut lines = header_section.split("\r\n");

    // First line: request or response
    let first_line_str = lines.next().ok_or(ParseError::EmptyFrame)?;
    let first_line = parse_first_line(first_line_str)?;

    // Remaining lines: headers
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() { continue; }
        let colon = line.find(':')
            .ok_or_else(|| ParseError::HeaderMalformed(line.to_string()))?;
        let name = line[..colon].trim().to_string();
        let value = line[colon + 1..].trim().to_string();
        if name.is_empty() {
            return Err(ParseError::HeaderMalformed(line.to_string()));
        }
        headers.push((name, value));
    }

    // Content-Length is mandatory (spec §1)
    let cl_str = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, v)| v.as_str())
        .ok_or(ParseError::MissingContentLength)?;

    let content_length: usize = cl_str.trim().parse()
        .map_err(|_| ParseError::BadContentLength(cl_str.to_string()))?;

    // Extract exactly content_length bytes from the body region
    let remaining = &text[body_start..];
    let remaining_bytes = remaining.as_bytes();
    if remaining_bytes.len() < content_length {
        return Err(ParseError::BodyTooShort {
            expected: content_length,
            got: remaining_bytes.len(),
        });
    }

    // Must land on a UTF-8 character boundary
    let body = std::str::from_utf8(&remaining_bytes[..content_length])
        .map_err(|_| ParseError::BodyNotUtf8)?
        .to_string();

    Ok(HttpFrame { first_line, headers, body })
}

fn parse_first_line(line: &str) -> Result<FirstLine, ParseError> {
    // Response: "HTTP/1.1 NNN Reason"
    if let Some(rest) = line.strip_prefix("HTTP/1.1 ") {
        let (status_str, reason) = rest.split_once(' ').unwrap_or((rest, ""));
        let status: u16 = status_str.parse()
            .map_err(|_| ParseError::InvalidFirstLine(line.to_string()))?;
        return Ok(FirstLine::Response { status, reason: reason.to_string() });
    }
    // Request: "VERB /path HTTP/1.1"
    let mut parts = line.splitn(3, ' ');
    let verb = parts.next().unwrap_or("");
    let path = parts.next().ok_or_else(|| ParseError::InvalidFirstLine(line.to_string()))?;
    let proto = parts.next().ok_or_else(|| ParseError::InvalidFirstLine(line.to_string()))?;
    if verb.is_empty() || path.is_empty() || proto != "HTTP/1.1" {
        return Err(ParseError::InvalidFirstLine(line.to_string()));
    }
    Ok(FirstLine::Request { verb: verb.to_string(), path: path.to_string() })
}

// ── Frame builder / accessors ─────────────────────────────────────────────────

impl HttpFrame {
    /// Create a request frame with no headers and an empty body.
    pub fn request(verb: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            first_line: FirstLine::Request { verb: verb.into(), path: path.into() },
            headers: Vec::new(),
            body: String::new(),
        }
    }

    /// Create a response frame with no headers and an empty body.
    pub fn response(status: u16, reason: impl Into<String>) -> Self {
        Self {
            first_line: FirstLine::Response { status, reason: reason.into() },
            headers: Vec::new(),
            body: String::new(),
        }
    }

    /// Verb of a request frame; `None` for response frames.
    pub fn verb(&self) -> Option<&str> {
        match &self.first_line {
            FirstLine::Request { verb, .. } => Some(verb),
            FirstLine::Response { .. } => None,
        }
    }

    /// Path of a request frame; `None` for response frames.
    pub fn path(&self) -> Option<&str> {
        match &self.first_line {
            FirstLine::Request { path, .. } => Some(path),
            FirstLine::Response { .. } => None,
        }
    }

    /// Status code of a response frame; `None` for request frames.
    pub fn status(&self) -> Option<u16> {
        match &self.first_line {
            FirstLine::Request { .. } => None,
            FirstLine::Response { status, .. } => Some(*status),
        }
    }

    /// Get the first header matching `name` (case-insensitive). Returns `None` if absent.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Append a header (builder pattern; does not deduplicate).
    #[must_use]
    pub fn add_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Replace the first matching header (case-insensitive), or append if absent.
    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        match self.headers.iter().position(|(k, _)| k.eq_ignore_ascii_case(name)) {
            Some(pos) => self.headers[pos].1 = value.into(),
            None => self.headers.push((name.to_string(), value.into())),
        }
    }

    /// Ensure `Content-Length` header matches `body.len()`. Call before `serialize()`.
    #[must_use]
    pub fn finalize(mut self) -> Self {
        let len = self.body.len();
        self.set_header("Content-Length", len.to_string());
        self
    }

    /// Serialize to wire-format string.
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        match &self.first_line {
            FirstLine::Request { verb, path } => {
                out.push_str(verb);
                out.push(' ');
                out.push_str(path);
                out.push_str(" HTTP/1.1\r\n");
            }
            FirstLine::Response { status, reason } => {
                out.push_str("HTTP/1.1 ");
                out.push_str(&status.to_string());
                out.push(' ');
                out.push_str(reason);
                out.push_str("\r\n");
            }
        }
        for (name, value) in &self.headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.push_str(&self.body);
        out
    }
}

// ── X-To shape validation (spec §5) ──────────────────────────────────────────

/// Validate that the `X-To` value matches the expected shape for a given verb+path (spec §5).
///
/// Returns `Ok(())` if the shape is correct, or `Err(description)` if not.
/// Verbs and paths not listed in spec §5 are passed through without validation.
pub fn validate_xto_shape(verb: &str, path: &str, xto: &str) -> Result<(), String> {
    match (verb, path) {
        ("POST", "/v1/posts") | ("POST", "/v1/reactions") => {
            parse_channel(xto)
                .map(|_| ())
                .map_err(|_| format!("X-To for {verb} {path} must be '#channel.project', got: '{xto}'"))
        }
        ("POST", "/v1/dms") => {
            parse_identity(xto)
                .map(|_| ())
                .map_err(|_| format!("X-To for POST /v1/dms must be 'name@project', got: '{xto}'"))
        }
        ("PUBLISH", "/v1/deliveries") => {
            if xto.is_empty() {
                return Err("X-To on PUBLISH /v1/deliveries must not be empty".to_string());
            }
            for part in xto.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    return Err("X-To on PUBLISH contains an empty recipient segment".to_string());
                }
                parse_identity(part)
                    .map_err(|_| format!("X-To on PUBLISH: '{part}' is not a valid name@project"))?;
            }
            Ok(())
        }
        // All other verb/path combinations are not validated here.
        _ => Ok(()),
    }
}

/// Parse a `name@project` identity string (spec §4).
///
/// Forbidden chars in `name` and `project`: `,`, `@`. `.` is valid in `project`.
/// Returns `(name, project)` slices on success, or `()` on failure.
pub fn parse_identity(s: &str) -> Result<(&str, &str), ()> {
    let at = s.find('@').ok_or(())?;
    let name = &s[..at];
    let project = &s[at + 1..];
    if name.is_empty() || project.is_empty() { return Err(()); }
    if name.contains(',') || name.contains('@') { return Err(()); }
    if project.contains(',') || project.contains('@') { return Err(()); }
    Ok((name, project))
}

/// Parse a `#channel.project` channel address (spec §4).
///
/// Requires `#` prefix. Splits on the first `.`. Returns `(channel, project)` on success.
pub fn parse_channel(s: &str) -> Result<(&str, &str), ()> {
    let s = s.strip_prefix('#').ok_or(())?;
    let dot = s.find('.').ok_or(())?;
    let channel = &s[..dot];
    let project = &s[dot + 1..];
    if channel.is_empty() || project.is_empty() { return Err(()); }
    Ok((channel, project))
}

/// Partition a PUBLISH X-To value into valid and invalid recipients.
///
/// X-To is a comma-separated list of `name@project` identities. Each part is
/// trimmed and validated with `parse_identity`. Returns:
/// - `valid`: owned strings that passed validation
/// - `invalid`: `(part, reason)` pairs for parts that failed
///
/// Empty parts (from trailing commas or double commas) are treated as invalid.
/// The caller should 400 if `valid` is empty, or 200 with `X-Dropped` if some
/// parts were dropped.
pub fn partition_publish_recipients(xto: &str) -> (Vec<String>, Vec<(String, String)>) {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for part in xto.split(',') {
        let part = part.trim();
        if part.is_empty() {
            invalid.push((part.to_string(), "empty recipient segment".to_string()));
            continue;
        }
        match parse_identity(part) {
            Ok(_) => valid.push(part.to_string()),
            Err(_) => invalid.push((part.to_string(), format!("'{}' is not a valid name@project", part))),
        }
    }
    (valid, invalid)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Round-trip tests ──────────────────────────────────────────────────────

    #[test]
    fn request_frame_round_trip() {
        let frame = HttpFrame::request("HELLO", "/v1/sessions")
            .add_header("X-From", "alice@TeamA")
            .finalize();
        let serialized = frame.serialize();
        let parsed = parse(&serialized).expect("parse round-trip");
        assert_eq!(parsed, frame);
    }

    #[test]
    fn response_frame_round_trip() {
        let frame = HttpFrame::response(200, "OK")
            .add_header("X-Session-Id", "sess-abc")
            .finalize();
        let serialized = frame.serialize();
        let parsed = parse(&serialized).expect("parse round-trip");
        assert_eq!(parsed, frame);
    }

    #[test]
    fn frame_with_body_round_trip() {
        let mut frame = HttpFrame::request("POST", "/v1/dms")
            .add_header("X-From", "alice@TeamA")
            .add_header("X-To", "bob@TeamB")
            .add_header("Content-Type", "text/markdown");
        frame.body = "Hello Bob!".to_string();
        let frame = frame.finalize();
        let serialized = frame.serialize();
        let parsed = parse(&serialized).expect("parse round-trip");
        assert_eq!(parsed.body, "Hello Bob!");
        assert_eq!(parsed.header("Content-Length"), Some("10"));
    }

    #[test]
    fn frame_with_crlf_in_body() {
        // Body may contain CRLF — must be preserved verbatim.
        let body = "line one\r\nline two\r\nline three";
        let mut frame = HttpFrame::request("POST", "/v1/posts")
            .add_header("X-From", "neo@Matrix")
            .add_header("X-To", "#general.Matrix");
        frame.body = body.to_string();
        let frame = frame.finalize();
        let serialized = frame.serialize();
        let parsed = parse(&serialized).expect("parse round-trip");
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn empty_body_content_length_zero() {
        let frame = HttpFrame::response(503, "Service Unavailable")
            .add_header("Retry-After", "1")
            .finalize();
        assert_eq!(frame.header("Content-Length"), Some("0"));
        let serialized = frame.serialize();
        let parsed = parse(&serialized).expect("parse round-trip");
        assert_eq!(parsed.body, "");
    }

    #[test]
    fn multi_header_frame_round_trip() {
        let mut frame = HttpFrame::request("PUBLISH", "/v1/deliveries")
            .add_header("X-From", "alice@TeamA")
            .add_header("X-To", "bob@TeamB,carol@TeamC")
            .add_header("X-Thread", "t-abc")
            .add_header("X-Post-Id", "p-xyz")
            .add_header("Content-Type", "text/markdown");
        frame.body = "A message body.".to_string();
        let frame = frame.finalize();
        let serialized = frame.serialize();
        let parsed = parse(&serialized).expect("parse round-trip");
        assert_eq!(parsed.header("X-Thread"), Some("t-abc"));
        assert_eq!(parsed.header("X-Post-Id"), Some("p-xyz"));
        assert_eq!(parsed.header("x-from"), Some("alice@TeamA")); // case-insensitive
    }

    #[test]
    fn deliver_frame_round_trip() {
        let mut frame = HttpFrame::request("DELIVER", "/v1/deliveries")
            .add_header("X-From", "alice@TeamA")
            .add_header("X-To", "bob@TeamB")
            .add_header("Content-Type", "text/markdown");
        frame.body = "Hello from Alice.".to_string();
        let frame = frame.finalize();
        let serialized = frame.serialize();
        let parsed = parse(&serialized).expect("round-trip");
        assert_eq!(parsed.verb(), Some("DELIVER"));
        assert_eq!(parsed.path(), Some("/v1/deliveries"));
        assert_eq!(parsed.status(), None);
    }

    // ── Header accessor tests ─────────────────────────────────────────────────

    #[test]
    fn header_lookup_case_insensitive() {
        let frame = HttpFrame::request("POST", "/v1/posts")
            .add_header("Content-Type", "text/markdown")
            .finalize();
        assert_eq!(frame.header("content-type"), Some("text/markdown"));
        assert_eq!(frame.header("CONTENT-TYPE"), Some("text/markdown"));
        assert_eq!(frame.header("Content-Type"), Some("text/markdown"));
        assert_eq!(frame.header("X-Missing"), None);
    }

    #[test]
    fn set_header_replaces_existing() {
        let mut frame = HttpFrame::response(200, "OK").finalize();
        frame.set_header("Content-Length", "42");
        assert_eq!(frame.header("Content-Length"), Some("42"));
        // Only one Content-Length header
        let cl_count = frame.headers.iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .count();
        assert_eq!(cl_count, 1);
    }

    #[test]
    fn add_header_appends() {
        let frame = HttpFrame::request("GET", "/v1/agents")
            .add_header("X-A", "1")
            .add_header("X-A", "2"); // duplicate — appended, not replaced
        assert_eq!(frame.headers.len(), 2);
    }

    // ── Parse error tests ─────────────────────────────────────────────────────

    #[test]
    fn parse_empty_string_returns_empty_frame_error() {
        assert_eq!(parse("").unwrap_err(), ParseError::EmptyFrame);
    }

    #[test]
    fn parse_missing_header_terminator() {
        let bad = "HELLO /v1/sessions HTTP/1.1\r\nX-From: alice@TeamA\r\n";
        assert_eq!(parse(bad).unwrap_err(), ParseError::MissingHeaderTerminator);
    }

    #[test]
    fn parse_missing_content_length() {
        let bad = "HELLO /v1/sessions HTTP/1.1\r\nX-From: alice@TeamA\r\n\r\n";
        assert_eq!(parse(bad).unwrap_err(), ParseError::MissingContentLength);
    }

    #[test]
    fn parse_bad_content_length() {
        let bad = "HELLO /v1/sessions HTTP/1.1\r\nContent-Length: abc\r\n\r\n";
        assert!(matches!(parse(bad).unwrap_err(), ParseError::BadContentLength(_)));
    }

    #[test]
    fn parse_body_shorter_than_content_length() {
        let bad = "HELLO /v1/sessions HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort";
        assert!(matches!(
            parse(bad).unwrap_err(),
            ParseError::BodyTooShort { expected: 100, got: 5 }
        ));
    }

    #[test]
    fn parse_malformed_header_no_colon() {
        let bad = "HELLO /v1/sessions HTTP/1.1\r\nNoColonHere\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(parse(bad).unwrap_err(), ParseError::HeaderMalformed(_)));
    }

    #[test]
    fn parse_invalid_first_line_no_path() {
        let bad = "HELLO HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(parse(bad).unwrap_err(), ParseError::InvalidFirstLine(_)));
    }

    #[test]
    fn parse_invalid_first_line_wrong_protocol() {
        let bad = "HELLO /v1/sessions HTTP/2\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(parse(bad).unwrap_err(), ParseError::InvalidFirstLine(_)));
    }

    #[test]
    fn parse_response_frame() {
        let text = "HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n";
        let frame = parse(text).unwrap();
        assert_eq!(frame.status(), Some(409));
        assert_eq!(frame.verb(), None);
        assert_eq!(frame.path(), None);
    }

    // ── parse_identity tests ──────────────────────────────────────────────────

    #[test]
    fn parse_identity_valid() {
        assert_eq!(parse_identity("alice@TeamA"), Ok(("alice", "TeamA")));
        assert_eq!(parse_identity("Boards@some.project"), Ok(("Boards", "some.project")));
    }

    #[test]
    fn parse_identity_no_at() {
        assert!(parse_identity("alice.TeamA").is_err());
        assert!(parse_identity("alice").is_err());
    }

    #[test]
    fn parse_identity_empty_components() {
        assert!(parse_identity("@TeamA").is_err());   // empty name
        assert!(parse_identity("alice@").is_err());   // empty project
        assert!(parse_identity("@").is_err());        // both empty
    }

    #[test]
    fn parse_identity_forbidden_chars() {
        assert!(parse_identity("ali,ce@TeamA").is_err());    // comma in name
        assert!(parse_identity("alice@Team,A").is_err());    // comma in project
        assert!(parse_identity("ali@ce@TeamA").is_err());    // extra @ in name
    }

    #[test]
    fn parse_identity_dot_in_project_is_valid() {
        // spec §4: '.' is valid in project name
        assert!(parse_identity("neo@AITeam.Platform").is_ok());
    }

    // ── parse_channel tests ───────────────────────────────────────────────────

    #[test]
    fn parse_channel_valid() {
        assert_eq!(parse_channel("#planning.TeamA"), Ok(("planning", "TeamA")));
        assert_eq!(parse_channel("#general.AITeam.Platform"), Ok(("general", "AITeam.Platform")));
    }

    #[test]
    fn parse_channel_no_hash() {
        assert!(parse_channel("planning.TeamA").is_err());
        assert!(parse_channel("general").is_err());
    }

    #[test]
    fn parse_channel_no_dot() {
        assert!(parse_channel("#planning").is_err());
    }

    #[test]
    fn parse_channel_empty_components() {
        assert!(parse_channel("#.TeamA").is_err());    // empty channel
        assert!(parse_channel("#planning.").is_err()); // empty project
    }

    // ── validate_xto_shape tests ──────────────────────────────────────────────

    #[test]
    fn xto_post_posts_requires_channel() {
        assert!(validate_xto_shape("POST", "/v1/posts", "#general.TeamA").is_ok());
        assert!(validate_xto_shape("POST", "/v1/posts", "alice@TeamA").is_err()); // identity not channel
        assert!(validate_xto_shape("POST", "/v1/posts", "general").is_err());
    }

    #[test]
    fn xto_post_reactions_requires_channel() {
        assert!(validate_xto_shape("POST", "/v1/reactions", "#analysis.TeamB").is_ok());
        assert!(validate_xto_shape("POST", "/v1/reactions", "alice@TeamA").is_err());
    }

    #[test]
    fn xto_post_dms_requires_identity() {
        assert!(validate_xto_shape("POST", "/v1/dms", "bob@TeamB").is_ok());
        assert!(validate_xto_shape("POST", "/v1/dms", "#general.TeamA").is_err()); // channel not identity
    }

    #[test]
    fn xto_publish_requires_comma_separated_identities() {
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "alice@A,bob@B").is_ok());
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "alice@A").is_ok()); // single is ok
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "").is_err());       // empty
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "alice@A,bad").is_err()); // no @
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "#chan.A,bob@B").is_err()); // channel mixed in
    }

    #[test]
    fn xto_unknown_verb_passes_through() {
        // Unknown verb/path combos are not rejected by this validator.
        assert!(validate_xto_shape("DELIVER", "/v1/deliveries", "anything").is_ok());
        assert!(validate_xto_shape("HELLO", "/v1/sessions", "").is_ok());
    }
}

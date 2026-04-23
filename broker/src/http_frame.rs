//! HttpFrame — HTTP-shaped text framing for WebSocket transport (spec §1).
//!
//! One frame per WS `Message::Text`. Frames are never split across messages.
//! `Content-Length` is optional (C3): when present, body is consumed as exactly that many bytes
//! (validated); when absent, body = entire remainder after `\r\n\r\n` (message boundary is safe).
//! Body may contain CR, LF, or CRLF — readers consume exactly Content-Length bytes when given.
//!
//! # Wire format
//! ```text
//! VERB /path HTTP/1.1\r\n          ← request frame (v1 — HTTP version suffix present)
//! VERB /path\r\n                   ← request frame (v2 — version suffix omitted, C1)
//! HTTP/1.1 NNN Reason\r\n          ← response frame
//! Header-Name: value\r\n           ← v1 header style (X-Foo: value)
//! header-name: value\r\n           ← v2 header style (foo: value); both accepted
//! Content-Length: N\r\n            ← optional (C3); broker-generated frames always include it
//! \r\n
//! <body — exactly N bytes if CL present, else full remainder>
//! ```

// ── Types ─────────────────────────────────────────────────────────────────────

/// The opening line of a frame — request or response shape.
#[derive(Debug, Clone, PartialEq)]
pub enum FirstLine {
    /// A request frame.
    /// - `inner_verb`: optional inner-verb token (C7 `PUBLISH POST /path` form). `None` for
    ///   standard 2-token frames. `serialize()` emits it between outer verb and path.
    /// - `has_version`: true when wire form included `HTTP/1.1` suffix; false for v2 agents
    ///   that omit it. `serialize()` preserves this (spec C1).
    Request { verb: String, inner_verb: Option<String>, path: String, has_version: bool },
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
/// # Spec §1 compliance (C3 update)
/// - Content-Length is **optional**. When present, body is consumed as exactly that many bytes
///   and the value is validated. When absent, body = entire remainder after `\r\n\r\n` (safe
///   because one WS message = one frame, so message boundary is the length delimiter).
/// - Serializer continues to emit Content-Length on broker-generated frames.
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

    // Content-Length is optional (C3). When present: validate and consume exactly that many bytes.
    // When absent: body = entire remainder (safe — one WS message = one frame).
    let cl_opt = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .map(|(_, v)| v.as_str());

    let remaining = &text[body_start..];
    let remaining_bytes = remaining.as_bytes();

    let content_length: usize = if let Some(cl_str) = cl_opt {
        cl_str.trim().parse()
            .map_err(|_| ParseError::BadContentLength(cl_str.to_string()))?
    } else {
        remaining_bytes.len()
    };

    // Extract exactly content_length bytes from the body region
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
    // Request — 2 to 4 tokens:
    //   VERB /path                           (v2, no version)
    //   VERB /path HTTP/1.1                  (v1, with version)
    //   VERB INNER_VERB /path                (C7, no version)
    //   VERB INNER_VERB /path HTTP/1.1       (C7, with version)
    // Disambiguation: if token[1] starts with '/' it IS the path; otherwise it is inner_verb.
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.len() < 2 {
        return Err(ParseError::InvalidFirstLine(line.to_string()));
    }
    let verb = parts[0];
    if verb.is_empty() {
        return Err(ParseError::InvalidFirstLine(line.to_string()));
    }

    let (inner_verb, path, version_tok): (Option<&str>, &str, Option<&str>) =
        if parts[1].starts_with('/') {
            // No inner_verb: VERB /path [HTTP/1.1]
            (None, parts[1], parts.get(2).copied())
        } else {
            // Has inner_verb: VERB INNER_VERB /path [HTTP/1.1]
            if parts.len() < 3 {
                return Err(ParseError::InvalidFirstLine(line.to_string()));
            }
            let iv = parts[1];
            let p = parts[2];
            if !p.starts_with('/') {
                return Err(ParseError::InvalidFirstLine(line.to_string()));
            }
            (Some(iv), p, parts.get(3).copied())
        };

    if path.is_empty() {
        return Err(ParseError::InvalidFirstLine(line.to_string()));
    }

    let has_version = match version_tok {
        Some("HTTP/1.1") => true,
        Some(_other) => return Err(ParseError::InvalidFirstLine(line.to_string())),
        None => false,
    };

    Ok(FirstLine::Request {
        verb: verb.to_string(),
        inner_verb: inner_verb.map(str::to_string),
        path: path.to_string(),
        has_version,
    })
}

// ── Frame builder / accessors ─────────────────────────────────────────────────

impl HttpFrame {
    /// Create a request frame with no headers and an empty body.
    /// Broker-generated frames always carry the HTTP/1.1 version suffix (`has_version: true`).
    pub fn request(verb: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            first_line: FirstLine::Request { verb: verb.into(), inner_verb: None, path: path.into(), has_version: true },
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

    /// Inner verb of a request frame (C7); `None` for standard frames and all response frames.
    pub fn inner_verb(&self) -> Option<&str> {
        match &self.first_line {
            FirstLine::Request { inner_verb, .. } => inner_verb.as_deref(),
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

    /// Dual-form header read: try `v1_name` first, fall back to `v2_name`.
    /// Use for headers that exist in both v1 (X-Foo) and v2 (foo) forms during transition.
    /// The lookup for each name is case-insensitive.
    pub fn header2<'a>(&'a self, v1_name: &str, v2_name: &str) -> Option<&'a str> {
        self.header(v1_name).or_else(|| self.header(v2_name))
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

    /// Remove all headers matching `name` (case-insensitive).
    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// Canonicalize sender identity: remove ALL `X-From` and `from:` headers, then add a
    /// single authoritative `from: identity` (v2). Prevents spoofed or duplicate sender
    /// headers from surviving alongside the broker-asserted identity (spec H2).
    pub fn set_canonical_from(&mut self, identity: &str) {
        self.remove_header("X-From");
        self.remove_header("from");
        self.headers.push(("from".to_string(), identity.to_string()));
    }

    /// Returns true if this is a response frame (has status, no verb).
    pub fn is_response(&self) -> bool {
        self.status().is_some() && self.verb().is_none()
    }

    /// Ensure `Content-Length` header matches `body.len()`. Call before `serialize()`.
    #[must_use]
    pub fn finalize(mut self) -> Self {
        let len = self.body.len();
        self.set_header("Content-Length", len.to_string());
        self
    }

    /// Serialize to wire-format string.
    ///
    /// For request frames, the `HTTP/1.1` version suffix is emitted only if the frame
    /// was parsed from a versioned first line (`has_version: true`). Broker-built frames
    /// always have `has_version: true`. This preserves "forward as-is" for v2 agents that
    /// omit the suffix (spec C1).
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        match &self.first_line {
            FirstLine::Request { verb, inner_verb, path, has_version } => {
                out.push_str(verb);
                out.push(' ');
                if let Some(iv) = inner_verb {
                    out.push_str(iv);
                    out.push(' ');
                }
                out.push_str(path);
                if *has_version {
                    out.push_str(" HTTP/1.1");
                }
                out.push_str("\r\n");
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
                .map_err(|_| format!("X-To for {verb} {path} must be '#channel.project' or '#channel@project', got: '{xto}'"))
        }
        ("POST", "/v1/dms") => {
            parse_identity(xto)
                .map(|_| ())
                .map_err(|_| format!("X-To for POST /v1/dms must be 'name@project', got: '{xto}'"))
        }
        // PUBLISH /v1/deliveries: broker trusts the pre-resolved mentions: list from Boards — no validation.
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

/// Parse a C6 agent-addressed resource path and extract `(name, project)`.
///
/// Accepts any path of the form `/agents/<name>@<project>/...` — e.g. `/agents/alice@TeamA/dms`.
/// The `<name>@<project>` segment is the first path component after `/agents/`; everything
/// after the next `/` is ignored (broker only needs the recipient identity for routing).
/// Returns `None` for paths that don't start with `/agents/` or have a malformed identity segment.
/// Parse a C6 agent-scoped DM path and extract `(name, project)`.
///
/// Only accepts exactly `/agents/<name>@<project>/dms`. Any other tail
/// (e.g. `/presence`, `/evil`, or no tail at all) returns `None` so the
/// caller can respond 400 rather than silently misrouting.
pub fn parse_identity_from_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/agents/")?;
    let seg_end = rest.find('/')?; // require a '/' after identity — no bare /agents/<id>
    let addr = &rest[..seg_end];
    let tail = &rest[seg_end..]; // e.g. "/dms"
    if tail != "/dms" {
        return None;
    }
    parse_identity(addr).ok()
}

/// Parse a C6 resource path and extract `(channel, project)` from the first path segment.
///
/// Accepts any path of the form `/channels/<channel>@<project>/...`.
/// The `<channel>@<project>` segment is the first path component after `/channels/`; everything
/// after the next `/` is ignored (broker only needs the project for routing).
/// Returns `None` for any path that does not start with `/channels/` or is malformed.
pub fn parse_channel_from_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/channels/")?;
    // Find the end of the channel@project segment (first '/' after the prefix, or end of string).
    let seg_end = rest.find('/').unwrap_or(rest.len());
    let addr = &rest[..seg_end];
    // addr must be `channel@project` — '@' is the C6 separator (no '#' prefix, no '.' separator here).
    let at = addr.find('@')?;
    let channel = &addr[..at];
    let project = &addr[at + 1..];
    if channel.is_empty() || project.is_empty() {
        return None;
    }
    Some((channel, project))
}

/// Parse a channel address (spec §4).
///
/// Accepts both v1 (`#channel.project`) and v2 (`#channel@project`) separator forms.
/// Requires `#` prefix. Splits on the first `.` or `@` (whichever appears first after `#`).
/// Returns `(channel, project)` on success. Empty channel or project → Err.
pub fn parse_channel(s: &str) -> Result<(&str, &str), ()> {
    let s = s.strip_prefix('#').ok_or(())?;
    // Find the first separator — either '.' (v1) or '@' (v2).
    let sep = s.find(['.', '@']).ok_or(())?;
    let channel = &s[..sep];
    let project = &s[sep + 1..];
    if channel.is_empty() || project.is_empty() { return Err(()); }
    Ok((channel, project))
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
    fn parse_no_content_length_infers_body_from_remainder() {
        // C3: Content-Length absent — body = entire remainder after \r\n\r\n.
        let text = "HELLO /v1/sessions HTTP/1.1\r\nX-From: alice@TeamA\r\n\r\nhello";
        let frame = parse(text).expect("frame without Content-Length should parse");
        assert_eq!(frame.verb(), Some("HELLO"));
        assert_eq!(frame.body, "hello");
    }

    #[test]
    fn parse_no_content_length_empty_body() {
        // C3: Content-Length absent, no body after \r\n\r\n — body is empty string.
        let text = "HELLO /v1/sessions HTTP/1.1\r\nX-From: alice@TeamA\r\n\r\n";
        let frame = parse(text).expect("frame without Content-Length and no body should parse");
        assert_eq!(frame.body, "");
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
        // A single-token line (no path at all) must fail.
        let bad = "HELLO\r\nContent-Length: 0\r\n\r\n";
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
        // v1 separator: '.'
        assert_eq!(parse_channel("#planning.TeamA"), Ok(("planning", "TeamA")));
        assert_eq!(parse_channel("#general.AITeam.Platform"), Ok(("general", "AITeam.Platform")));
        // v2 separator: '@'
        assert_eq!(parse_channel("#planning@TeamA"), Ok(("planning", "TeamA")));
        assert_eq!(parse_channel("#general@AITeam.Platform"), Ok(("general", "AITeam.Platform")));
        // v2 with dotted project: '@' is separator, project contains '.'
        assert_eq!(parse_channel("#analysis@Org.Sub"), Ok(("analysis", "Org.Sub")));
    }

    #[test]
    fn parse_channel_no_hash() {
        assert!(parse_channel("planning.TeamA").is_err());
        assert!(parse_channel("general").is_err());
    }

    #[test]
    fn parse_channel_no_separator() {
        // Neither '.' nor '@' after '#' — invalid
        assert!(parse_channel("#planning").is_err());
    }

    #[test]
    fn parse_channel_empty_components() {
        assert!(parse_channel("#.TeamA").is_err());    // empty channel (v1)
        assert!(parse_channel("#planning.").is_err()); // empty project (v1)
        assert!(parse_channel("#@TeamA").is_err());    // empty channel (v2)
        assert!(parse_channel("#planning@").is_err()); // empty project (v2)
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
    fn xto_publish_passes_through() {
        // C13: broker trusts Boards' pre-resolved mentions: list — PUBLISH X-To is not validated.
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "alice@A,bob@B").is_ok());
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "").is_ok());
        assert!(validate_xto_shape("PUBLISH", "/v1/deliveries", "bad-identity").is_ok());
    }

    #[test]
    fn xto_unknown_verb_passes_through() {
        // Unknown verb/path combos are not rejected by this validator.
        assert!(validate_xto_shape("DELIVER", "/v1/deliveries", "anything").is_ok());
        assert!(validate_xto_shape("HELLO", "/v1/sessions", "").is_ok());
    }

    // ── header2 dual-form read tests ─────────────────────────────────────────

    #[test]
    fn header2_returns_v1_when_present() {
        let frame = HttpFrame::request("POST", "/v1/dms")
            .add_header("X-To", "alice@TeamA")
            .finalize();
        assert_eq!(frame.header2("X-To", "to"), Some("alice@TeamA"));
    }

    #[test]
    fn header2_falls_back_to_v2_when_v1_absent() {
        let frame = HttpFrame::request("POST", "/v1/dms")
            .add_header("to", "alice@TeamA")
            .finalize();
        assert_eq!(frame.header2("X-To", "to"), Some("alice@TeamA"));
    }

    #[test]
    fn header2_v1_wins_when_both_present() {
        let frame = HttpFrame::request("POST", "/v1/dms")
            .add_header("X-To", "v1@TeamA")
            .add_header("to", "v2@TeamA")
            .finalize();
        assert_eq!(frame.header2("X-To", "to"), Some("v1@TeamA"));
    }

    #[test]
    fn header2_returns_none_when_neither_present() {
        let frame = HttpFrame::request("POST", "/v1/dms").finalize();
        assert_eq!(frame.header2("X-To", "to"), None);
    }

    #[test]
    fn set_canonical_from_sets_from_and_strips_xfrom() {
        let mut frame = HttpFrame::request("POST", "/v1/posts")
            .add_header("from", "attacker@evil")   // v2 spoofed identity
            .add_header("X-From", "attacker@evil") // v1 spoofed identity
            .finalize();
        frame.set_canonical_from("alice@TeamA");
        assert_eq!(frame.header("from"), Some("alice@TeamA"), "from: must be set to canonical identity");
        assert_eq!(frame.header("X-From"), None, "X-From must be stripped after canonicalization");
        // Only one from: header
        let from_count = frame.headers.iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("from"))
            .count();
        assert_eq!(from_count, 1, "exactly one from: must remain");
    }

    #[test]
    fn set_canonical_from_purges_duplicate_from_headers() {
        // Attacker sends multiple X-From + from: headers. All must be removed; only the
        // broker-asserted identity survives as a single from: header.
        let mut frame = HttpFrame::request("POST", "/v1/posts")
            .add_header("X-From", "evil1@proj")
            .add_header("from", "evil2@proj")
            .add_header("X-From", "evil3@proj")
            .finalize();
        frame.set_canonical_from("alice@proj");
        assert_eq!(frame.header("from"), Some("alice@proj"), "canonical from: must be alice@proj");
        assert_eq!(frame.header("X-From"), None, "X-From must be gone");
        let from_count = frame.headers.iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("from"))
            .count();
        assert_eq!(from_count, 1, "exactly one from: must remain — all attacker copies removed");
    }

    #[test]
    fn set_canonical_from_works_when_no_from_present() {
        let mut frame = HttpFrame::request("POST", "/v1/posts").finalize();
        frame.set_canonical_from("alice@TeamA");
        assert_eq!(frame.header("from"), Some("alice@TeamA"));
        assert_eq!(frame.header("X-From"), None);
    }

    // ── C1 request-line no-version tests ────────────────────────────────────

    #[test]
    fn parse_request_no_version_suffix_accepted() {
        // v2 agents may omit "HTTP/1.1" from the request line — broker must accept.
        let text = "POST /v1/dms\r\nX-From: alice@TeamA\r\nContent-Length: 0\r\n\r\n";
        let frame = parse(text).expect("no-version frame should parse");
        assert_eq!(frame.verb(), Some("POST"));
        assert_eq!(frame.path(), Some("/v1/dms"));
        // has_version is false — serialize() must NOT add HTTP/1.1 suffix
        let serialized = frame.serialize();
        assert!(serialized.starts_with("POST /v1/dms\r\n"), "first line must be preserved without version: {serialized:?}");
    }

    #[test]
    fn parse_request_with_version_suffix_still_accepted() {
        // v1 form with HTTP/1.1 still works after C1 change.
        let text = "POST /v1/dms HTTP/1.1\r\nX-From: alice@TeamA\r\nContent-Length: 0\r\n\r\n";
        let frame = parse(text).expect("versioned frame should parse");
        let serialized = frame.serialize();
        assert!(serialized.starts_with("POST /v1/dms HTTP/1.1\r\n"), "v1 form must round-trip: {serialized:?}");
    }

    #[test]
    fn parse_request_unknown_version_still_rejected() {
        // An unrecognized third token is still an error (not silently ignored).
        let bad = "POST /v1/dms HTTP/2\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(parse(bad).unwrap_err(), ParseError::InvalidFirstLine(_)));
    }

    // ── C7 inner_verb tests ──────────────────────────────────────────

    #[test]
    fn parse_inner_verb_no_version() {
        // C7 form: VERB INNER_VERB /path (3 tokens, no HTTP/1.1)
        let text = "PUBLISH POST /channels/general@proj/threads/t-1/posts/p-91\r\nContent-Length: 0\r\n\r\n";
        let frame = parse(text).expect("C7 no-version should parse");
        assert_eq!(frame.verb(), Some("PUBLISH"));
        assert_eq!(frame.inner_verb(), Some("POST"));
        assert_eq!(frame.path(), Some("/channels/general@proj/threads/t-1/posts/p-91"));
        assert!(!matches!(&frame.first_line, super::FirstLine::Request { has_version: true, .. }));
        // Serialize must not add HTTP/1.1
        let s = frame.serialize();
        assert!(s.starts_with("PUBLISH POST /channels/general@proj/threads/t-1/posts/p-91\r\n"),
            "C7 no-version must round-trip: {s:?}");
    }

    #[test]
    fn parse_inner_verb_with_version() {
        // C7 form: VERB INNER_VERB /path HTTP/1.1 (4 tokens)
        let text = "PUBLISH POST /channels/general@proj/threads/t-1/posts/p-91 HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
        let frame = parse(text).expect("C7 versioned should parse");
        assert_eq!(frame.verb(), Some("PUBLISH"));
        assert_eq!(frame.inner_verb(), Some("POST"));
        assert_eq!(frame.path(), Some("/channels/general@proj/threads/t-1/posts/p-91"));
        let s = frame.serialize();
        assert!(s.starts_with("PUBLISH POST /channels/general@proj/threads/t-1/posts/p-91 HTTP/1.1\r\n"),
            "C7 versioned must round-trip: {s:?}");
    }

    #[test]
    fn inner_verb_none_for_standard_frame() {
        let frame = super::HttpFrame::request("POST", "/v1/posts");
        assert_eq!(frame.inner_verb(), None, "standard frame must have no inner_verb");
    }

    #[test]
    fn deliver_frame_carries_inner_verb() {
        // A DELIVER frame constructed with inner_verb round-trips correctly.
        use super::FirstLine;
        let mut frame = super::HttpFrame::request("DELIVER", "/channels/general@proj/threads/t-1/posts/p-91");
        frame.first_line = FirstLine::Request {
            verb: "DELIVER".to_string(),
            inner_verb: Some("POST".to_string()),
            path: "/channels/general@proj/threads/t-1/posts/p-91".to_string(),
            has_version: true,
        };
        let s = frame.serialize();
        assert!(s.starts_with("DELIVER POST /channels/general@proj/threads/t-1/posts/p-91 HTTP/1.1\r\n"),
            "DELIVER with inner_verb must serialize correctly: {s:?}");
    }

    // ── Pass-through guarantee test ──────────────────────────────────────────

    #[test]
    fn unknown_headers_survive_serialize_round_trip() {
        // Headers the broker does not read must be preserved verbatim through parse+serialize.
        let text = "POST /v1/posts HTTP/1.1\r\nX-Thread: t-abc\r\nthread: t-abc\r\nX-Post-Id: p-xyz\r\ncustom-v2-header: some-value\r\nContent-Length: 0\r\n\r\n";
        let frame = parse(text).expect("parse");
        let serialized = frame.serialize();
        let reparsed = parse(&serialized).expect("re-parse");
        assert_eq!(reparsed.header("X-Thread"), Some("t-abc"));
        assert_eq!(reparsed.header("thread"), Some("t-abc"));
        assert_eq!(reparsed.header("X-Post-Id"), Some("p-xyz"));
        assert_eq!(reparsed.header("custom-v2-header"), Some("some-value"));
    }

    // ── parse_identity_from_path tests (C6 agent paths) ─────────────────────

    #[test]
    fn parse_identity_from_path_basic() {
        assert_eq!(
            parse_identity_from_path("/agents/alice@TeamA/dms"),
            Some(("alice", "TeamA"))
        );
        assert_eq!(
            parse_identity_from_path("/agents/Bob@AITeam.Platform/dms"),
            Some(("Bob", "AITeam.Platform"))
        );
    }

    #[test]
    fn parse_identity_from_path_no_tail() {
        // No trailing slash — must return None (not a DM path).
        assert_eq!(parse_identity_from_path("/agents/alice@proj"), None);
    }

    #[test]
    fn parse_identity_from_path_rejects_arbitrary_tail() {
        // Arbitrary tail must not route as DM.
        assert_eq!(parse_identity_from_path("/agents/Bob@proj/evil"), None);
        assert_eq!(parse_identity_from_path("/agents/Bob@proj/presence"), None);
        assert_eq!(parse_identity_from_path("/agents/Bob@proj/notifications"), None);
    }

    #[test]
    fn parse_identity_from_path_not_an_agent_path() {
        assert_eq!(parse_identity_from_path("/v1/dms"), None);
        assert_eq!(parse_identity_from_path("/channels/general@proj/posts"), None);
        assert_eq!(parse_identity_from_path(""), None);
    }

    #[test]
    fn parse_identity_from_path_malformed_segment() {
        // No '@' in identity segment → None.
        assert_eq!(parse_identity_from_path("/agents/alice.TeamA/dms"), None);
        // Empty name → None.
        assert_eq!(parse_identity_from_path("/agents/@proj/dms"), None);
        // Empty project → None.
        assert_eq!(parse_identity_from_path("/agents/alice@/dms"), None);
    }

    // ── parse_channel_from_path tests (C6 resource paths) ───────────────────

    #[test]
    fn parse_channel_from_path_basic() {
        // Simplest form: /channels/<c>@<p>/<tail>
        assert_eq!(
            parse_channel_from_path("/channels/general@AITeam.Platform/posts"),
            Some(("general", "AITeam.Platform"))
        );
        assert_eq!(
            parse_channel_from_path("/channels/planning@MyOrg/reactions"),
            Some(("planning", "MyOrg"))
        );
    }

    #[test]
    fn parse_channel_from_path_deep_subpath() {
        // Full C6 path with thread/post segments — broker only needs the first segment.
        assert_eq!(
            parse_channel_from_path("/channels/general@AITeam.Platform/threads/t-7/posts/p-91"),
            Some(("general", "AITeam.Platform"))
        );
        assert_eq!(
            parse_channel_from_path("/channels/analysis@Org/threads/t-1/posts/p-2/reactions"),
            Some(("analysis", "Org"))
        );
    }

    #[test]
    fn parse_channel_from_path_no_tail() {
        // Channel root with no trailing segment — still valid (address alone).
        assert_eq!(
            parse_channel_from_path("/channels/general@proj"),
            Some(("general", "proj"))
        );
    }

    #[test]
    fn parse_channel_from_path_not_a_channel_path() {
        // v1 paths and unrelated paths return None.
        assert_eq!(parse_channel_from_path("/v1/posts"), None);
        assert_eq!(parse_channel_from_path("/v1/dms"), None);
        assert_eq!(parse_channel_from_path("/agents/alice@proj/dms"), None);
        assert_eq!(parse_channel_from_path("/tools/my-tool"), None);
        assert_eq!(parse_channel_from_path(""), None);
    }

    #[test]
    fn parse_channel_from_path_malformed_segment() {
        // Missing '@' in channel@project segment → None.
        assert_eq!(parse_channel_from_path("/channels/general/posts"), None);
        // Empty channel name → None.
        assert_eq!(parse_channel_from_path("/channels/@proj/posts"), None);
        // Empty project name → None.
        assert_eq!(parse_channel_from_path("/channels/general@/posts"), None);
    }
}

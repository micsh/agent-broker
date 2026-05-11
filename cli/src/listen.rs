use crate::identity::{self, Identity};
use crate::ws_session;
use anyhow::{Result, anyhow};
use futures_util::StreamExt;
#[cfg(windows)]
use futures_util::SinkExt;
use serde_json::{Value, json};
use std::io::Write;
use tokio_tungstenite::tungstenite::Message;

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn emit(v: Value) {
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    let _ = writeln!(h, "{}", serde_json::to_string(&v).unwrap());
    let _ = h.flush();
}

/// Convert a raw HttpFrame text into an NDJSON event.
/// Emits `event: "deliver"` for request verbs, `event: "response"` for status lines,
/// and `event: "frame"` for anything else.
fn frame_to_json(raw: &str) -> Value {
    let (head, body) = if let Some(idx) = raw.find("\r\n\r\n") {
        (&raw[..idx], &raw[idx + 4..])
    } else {
        (raw, "")
    };

    let mut lines = head.split("\r\n");
    let first_line = lines.next().unwrap_or("");

    // Collect headers into a JSON object.
    let mut headers = serde_json::Map::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim().to_ascii_lowercase();
            let val = line[colon + 1..].trim();
            headers.insert(key, json!(val));
        }
    }

    // Classify first line: status response vs. verb request.
    let parts: Vec<&str> = first_line.splitn(4, ' ').collect();
    let (event, verb, path) = match parts.as_slice() {
        // Status line: `200 OK` or `200 OK HTTP/1.1` (status code first token)
        [status, ..] if status.parse::<u16>().is_ok() => {
            ("response", *status, parts.get(1).copied().unwrap_or(""))
        }
        // Request: `VERB /path` or `VERB INNER /path [HTTP/1.1]`
        [verb, second, ..] => {
            // If second token starts with '/', it is the path; otherwise inner_verb then path.
            let path = if second.starts_with('/') {
                second
            } else {
                parts.get(2).copied().unwrap_or("")
            };
            ("deliver", *verb, path)
        }
        _ => ("frame", "", ""),
    };

    json!({
        "event": event,
        "verb": verb,
        "path": path,
        "headers": headers,
        "body": body,
        "ts": now(),
    })
}

/// Run one WS session: HELLO → CHALLENGE → AUTH → stream DELIVER frames.
/// On Windows, also opens a named pipe so sibling `dm`/`post` commands can
/// forward frames through the already-authenticated WS connection.
async fn session(id: &Identity, signing_key: &ed25519_dalek::SigningKey) -> Result<()> {
    let (mut tx, mut rx, ok_raw) = ws_session::handshake(id, signing_key).await?;
    // tx is only used in the Windows pipe-forward loop; keep alive on all platforms.
    #[cfg(not(windows))]
    let _ = &mut tx;

    let identity_str = id.fq();
    let pending: u64 = ws_session::extract_header(&ok_raw, "X-Pending-Count")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    emit(json!({
        "event": "connected",
        "as": identity_str,
        "pending": pending,
        "ts": now(),
    }));

    // ── Named pipe IPC — Windows only ────────────────────────────────────────
    // On Windows: spin up the pipe accept loop and run a select! loop that
    // routes pipe-forwarded frames over the live WS connection.
    // On other platforms: simple while-let stream loop.

    #[cfg(windows)]
    {
        let (pipe_req_tx, mut pipe_req_rx) =
            tokio::sync::mpsc::channel::<crate::pipe::PipeReq>(8);
        let name = crate::pipe::pipe_name(&id.project, &id.name);

        // Abort the accept_loop task when this scope exits (WS closed, errored,
        // or reconnecting) so `first_pipe_instance(true)` is released and the
        // next session can reclaim it without ERROR_ACCESS_DENIED.
        struct AbortOnDrop(tokio::task::JoinHandle<()>);
        impl Drop for AbortOnDrop {
            fn drop(&mut self) { self.0.abort(); }
        }
        let _pipe_task = AbortOnDrop(tokio::spawn(crate::pipe::accept_loop(name, pipe_req_tx)));

        // When a pipe request is forwarded over WS, the next HTTP status line
        // from the server is routed back to the pipe client via this sender.
        let mut pending_reply: Option<tokio::sync::oneshot::Sender<String>> = None;

        loop {
            tokio::select! {
                msg = rx.next() => {
                    match msg {
                        Some(Ok(Message::Text(t))) => {
                            let text = t.as_str();
                            // Route HTTP status responses to a pending pipe reply.
                            if text.starts_with("HTTP/") {
                                if let Some(reply_tx) = pending_reply.take() {
                                    let _ = reply_tx.send(text.to_string());
                                    continue;
                                }
                            }
                            emit(frame_to_json(text));
                        }
                        Some(Ok(Message::Close(c))) => {
                            emit(json!({
                                "event": "closed",
                                "reason": c.map(|f| f.reason.to_string()),
                                "ts": now(),
                            }));
                            return Ok(());
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => return Err(e.into()),
                        None => break,
                    }
                }
                req = pipe_req_rx.recv() => {
                    if let Some(req) = req {
                        let (frame, reply_tx) = (req.frame, req.reply_tx);
                        match tx.send(Message::Text(frame.into())).await {
                            Ok(()) => {
                                pending_reply = Some(reply_tx);
                            }
                            Err(e) => {
                                let resp = format!("HTTP/1.1 500 WS Send Error\r\n\r\n{e}");
                                let _ = reply_tx.send(resp);
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Non-Windows: simple stream loop (no pipe IPC) ─────────────────────────
    #[cfg(not(windows))]
    while let Some(msg) = rx.next().await {
        match msg? {
            Message::Text(t) => emit(frame_to_json(t.as_str())),
            Message::Close(c) => {
                emit(json!({
                    "event": "closed",
                    "reason": c.map(|f| f.reason.to_string()),
                    "ts": now(),
                }));
                return Ok(());
            }
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
        }
    }

    emit(json!({ "event": "closed", "reason": null, "ts": now() }));
    Ok(())
}

/// Run the listener. With `reconnect`, retries with exponential backoff (1s → 30s cap)
/// and emits `{"event":"reconnecting", ...}` between attempts.
pub async fn run(id: &Identity, reconnect: bool) -> Result<()> {
    // Pre-validate key exists before entering the retry loop.
    let signing_key = identity::load_ed25519_key(&id.project, &id.name)
        .ok_or_else(|| anyhow!(
            "no Ed25519 key for {}@{}. Run `broker register` first.",
            id.name, id.project
        ))?;

    let mut backoff = 1u64;
    loop {
        match session(id, &signing_key).await {
            Ok(()) if !reconnect => return Ok(()),
            Ok(()) => {
                backoff = 1;
            }
            Err(e) if !reconnect => return Err(e),
            Err(e) => {
                emit(json!({
                    "event": "reconnecting",
                    "error": e.to_string(),
                    "in_secs": backoff,
                    "ts": now(),
                }));
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

// §0 compliance: all WebSocket communication uses Message::Text (UTF-8 encoded).
// Message::Binary is never sent or accepted. HttpFrame framing per spec §1 (Cycle 12).
use crate::api::routes::AppState;
use crate::broker::state::{AgentState, BrokerState};
use crate::http_frame::{self, FirstLine, HttpFrame};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use base64::Engine;
use futures::stream::StreamExt;
use futures::SinkExt;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;
use uuid::Uuid;

/// Append a wire-log entry (headers only, no body) to the optional log channel.
/// Best-effort: formats to a String and calls `try_send` — silently drops if the
/// channel is full. Never blocks, never panics.
/// Format:
/// ```text
/// [INBOUND] 2026-04-23T04:01:00Z
/// POST /agents/Tesla@AITeam.Platform/dms
/// from: Operator@CopilotCli
/// → <outcome>
/// ```
fn log_wire(
    wire_log: &Option<Arc<SyncSender<String>>>,
    direction: &str,
    wire_bytes: &str,
    outcome: &str,
) {
    let Some(sender) = wire_log else { return };
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    // Log the headers block (before \r\n\r\n separator) of the actual wire bytes.
    // Using the serialized string ensures has_version is faithfully reproduced (e.g.
    // relay frames forwarded with HTTP/1.1 appear correctly in the log).
    let headers_block = wire_bytes
        .split("\r\n\r\n")
        .next()
        .unwrap_or(wire_bytes)
        .replace("\r\n", "\n");
    let entry = format!("{direction} {ts}\n{headers_block}\n→ {outcome}\n\n");
    let _ = sender.try_send(entry); // silently drop if channel full — never blocks routing
}

pub async fn handle_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, state))
}

// ── Frame I/O helpers ─────────────────────────────────────────────────────────

/// Send a single HttpFrame as a UTF-8 WS text message. Returns false if the send failed.
async fn send_frame(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    frame: &HttpFrame,
) -> bool {
    sender.send(Message::Text(frame.serialize().into())).await.is_ok()
}

/// Receive and parse the next HttpFrame from the WS stream.
/// Returns None on connection close or unrecoverable parse error.
async fn recv_frame(
    receiver: &mut futures::stream::SplitStream<WebSocket>,
) -> Option<HttpFrame> {
    while let Some(next) = receiver.next().await {
        let msg = match next {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("recv_frame: WS error: {e}");
                return None;
            }
        };
        match msg {
            Message::Text(t) => match http_frame::parse(&t) {
                Ok(f) => return Some(f),
                Err(e) => {
                    tracing::warn!("HttpFrame parse error: {e}");
                    return None;
                }
            },
            Message::Close(_) => return None,
            _ => continue,
        }
    }
    None
}

/// Build a plain response frame (no body, no extra headers).
fn error_response(status: u16, reason: &str) -> HttpFrame {
    HttpFrame::response(status, reason).finalize()
}

/// Build a response frame with a machine-readable X-Error-Code header.
fn error_response_with_code(status: u16, code: &str, reason: &str) -> HttpFrame {
    let mut frame = HttpFrame::response(status, reason);
    frame.set_header("X-Error-Code", code);
    frame.finalize()
}

// ── Handshake ─────────────────────────────────────────────────────────────────

/// Perform the four-frame Ed25519 handshake: HELLO → CHALLENGE → AUTH → (caller sends 200/409).
///
/// Returns `(name, project)` on success; sends an error frame and returns `None` on failure.
///
/// Boards path (name == "Boards") — TOFU bootstrap rule (spec §6):
///   • No stored key for Boards@project → token gate first (X-Registration-Token must match
///     `BrokerConfig::boards_registration_token`; 401 AUTH_INVALID_TOKEN if absent/wrong).
///     If token passes: X-Pubkey required; write once then CHALLENGE.
///     If no token is configured in broker, TOFU is disabled (401).
///   • Stored key exists → X-Pubkey must be absent OR byte-equal to stored key.
///     Differing X-Pubkey → 401 KEY_MISMATCH, BEFORE CHALLENGE is issued (no rotation from wire).
///
/// Agent path (name != "Boards"):
///   X-Pubkey is silently ignored (spec §6 — no pubkey rotation from the wire).
///   Agent must be pre-registered with a stored pubkey.
async fn wait_for_handshake(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    receiver: &mut futures::stream::SplitStream<WebSocket>,
    state: &Arc<AppState>,
) -> Option<(String, String)> {
    let frame = recv_frame(receiver).await?;

    // Must be HELLO /v1/sessions
    if frame.verb() != Some("HELLO") || frame.path() != Some("/v1/sessions") {
        if frame.status().is_some() {
            tracing::warn!(
                "Expected HELLO request, received response frame (status {:?})",
                frame.status()
            );
        }
        let _ = send_frame(sender, &error_response_with_code(400, "PROTOCOL_ERROR", "Bad Request")).await;
        return None;
    }

    let xfrom = match frame.header2("X-From", "from") {
        Some(v) => v.to_string(),
        None => {
            let _ = send_frame(sender, &error_response(400, "Bad Request")).await;
            return None;
        }
    };

    let (name, project) = match http_frame::parse_identity(&xfrom) {
        Ok((n, p)) => (n.to_string(), p.to_string()),
        Err(_) => {
            let _ = send_frame(sender, &error_response(400, "Bad Request")).await;
            return None;
        }
    };

    let xpubkey = frame.header2("X-Pubkey", "pubkey").map(|s| s.to_string());

    if name == "Boards" {
        // TOFU bootstrap rule (spec §6): check for an existing stored key first.
        let stored_hex = state.broker.repo.get_agent_public_key("Boards", &project);
        match stored_hex {
            None => {
                // Token gate (spec §6): TOFU is gated behind a shared secret configured at
                // startup via BOARDS_REGISTRATION_TOKEN. If not configured, TOFU is disabled.
                match &state.config.boards_registration_token {
                    None => {
                        tracing::warn!(
                            "Boards@{} TOFU attempt but BOARDS_REGISTRATION_TOKEN is not configured",
                            project
                        );
                        let _ = send_frame(
                            sender,
                            &error_response_with_code(401, "AUTH_INVALID_TOKEN", "Unauthorized"),
                        )
                        .await;
                        return None;
                    }
                    Some(expected) => {
                        let provided = match frame.header2("X-Registration-Token", "registration-token") {
                            Some(t) => t.to_string(),
                            None => {
                                tracing::warn!(
                                    "Boards@{} TOFU missing X-Registration-Token header",
                                    project
                                );
                                let _ = send_frame(
                                    sender,
                                    &error_response_with_code(401, "AUTH_INVALID_TOKEN", "Unauthorized"),
                                )
                                .await;
                                return None;
                            }
                        };
                        if provided != *expected {
                            tracing::warn!("Boards@{} TOFU X-Registration-Token mismatch", project);
                            let _ = send_frame(
                                sender,
                                &error_response_with_code(401, "AUTH_INVALID_TOKEN", "Unauthorized"),
                            )
                            .await;
                            return None;
                        }
                    }
                }
                // Token verified — X-Pubkey required for first-time registration.
                let pubkey_b64 = match xpubkey {
                    Some(ref k) => k.clone(),
                    None => {
                        tracing::warn!(
                            "Boards HELLO missing X-Pubkey for unregistered Boards@{}",
                            project
                        );
                        let _ = send_frame(sender, &error_response(400, "Bad Request")).await;
                        return None;
                    }
                };
                let pubkey_bytes = match base64::engine::general_purpose::STANDARD.decode(&pubkey_b64) {
                    Ok(b) => b,
                    Err(_) => {
                        let _ = send_frame(sender, &error_response(400, "Bad Request")).await;
                        return None;
                    }
                };
                let pubkey_hex = hex::encode(&pubkey_bytes);
                // Auto-create project if it doesn't exist — Boards connects via WS only,
                // there is no separate provisioning step. Use a random sentinel key; Boards
                // never uses project-key auth so no one needs to know it.
                if !state.broker.repo.project_exists(&project) {
                    let sentinel = Uuid::new_v4().to_string();
                    if let Err(e) = state.broker.repo.register_project(&project, &sentinel) {
                        tracing::warn!(
                            "Boards TOFU auto-create project '{}' failed: {}",
                            project,
                            e
                        );
                        let _ = send_frame(sender, &error_response(500, "Internal Server Error")).await;
                        return None;
                    }
                    tracing::info!("Boards@{}: TOFU — auto-created project row", project);
                }
                // register_agent is a no-op if row exists (project now guaranteed to exist).
                if let Err(e) = state.broker.repo.register_agent("Boards", &project, "service", "") {
                    tracing::warn!("Boards TOFU register_agent failed for project '{}': {}", project, e);
                    let _ = send_frame(sender, &error_response(403, "Forbidden")).await;
                    return None;
                }
                if let Err(e) = state.broker.repo.set_agent_public_key("Boards", &project, &pubkey_hex) {
                    tracing::warn!("Boards TOFU set_agent_public_key failed for project '{}': {}", project, e);
                    let _ = send_frame(sender, &error_response(500, "Internal Server Error")).await;
                    return None;
                }
                tracing::info!("Boards@{}: TOFU — first key registered", project);
            }
            Some(stored_hex) => {
                // Key already stored — X-Pubkey must be absent or byte-equal. No rotation from wire.
                if let Some(ref wire_b64) = xpubkey {
                    let wire_bytes = match base64::engine::general_purpose::STANDARD.decode(wire_b64) {
                        Ok(b) => b,
                        Err(_) => {
                            let _ = send_frame(sender, &error_response(400, "Bad Request")).await;
                            return None;
                        }
                    };
                    let wire_hex = hex::encode(&wire_bytes);
                    if wire_hex != stored_hex {
                        // Rotation attempt — reject BEFORE issuing CHALLENGE (spec §6).
                        tracing::warn!(
                            "Boards@{} key rotation rejected — wire X-Pubkey differs from stored key",
                            project
                        );
                        let _ = send_frame(
                            sender,
                            &error_response_with_code(401, "KEY_MISMATCH", "Unauthorized"),
                        )
                        .await;
                        return None;
                    }
                }
                // X-Pubkey absent or byte-equal — proceed to CHALLENGE using stored key.
            }
        }
    } else if xpubkey.is_some() {
        // Agent HELLO with X-Pubkey — spec §6: MUST ignore, no pubkey rotation from wire.
        tracing::warn!(
            "Agent HELLO from {}@{} carried X-Pubkey — ignoring (spec §6: no pubkey rotation from wire)",
            name, project
        );
    }

    // Common path: agent must be registered and have a stored pubkey.
    if !state.broker.repo.agent_exists(&name, &project) {
        tracing::warn!("HELLO from unregistered agent {}@{}", name, project);
        let _ = send_frame(sender, &error_response_with_code(403, "AUTH_INVALID_CREDS", "Forbidden")).await;
        return None;
    }
    let pubkey_hex = match state.broker.repo.get_agent_public_key(&name, &project) {
        Some(k) => k,
        None => {
            tracing::warn!("HELLO from {}@{} — no public key registered", name, project);
            let _ = send_frame(sender, &error_response_with_code(403, "AUTH_INVALID_CREDS", "Forbidden")).await;
            return None;
        }
    };

    // Issue challenge
    let identity = format!("{}@{}", name, project);
    let (nonce_bytes, nonce_b64, _payload) = state.broker.nonce_store.issue(&identity);
    let nonce_hex = hex::encode(nonce_bytes);

    let challenge = HttpFrame::request("CHALLENGE", "/v1/sessions")
        .add_header("X-Nonce", &nonce_b64)
        .finalize();
    if !send_frame(sender, &challenge).await {
        return None;
    }

    // Receive AUTH
    let auth_frame = recv_frame(receiver).await?;
    if auth_frame.verb() != Some("AUTH") || auth_frame.path() != Some("/v1/sessions") {
        let _ = send_frame(sender, &error_response_with_code(400, "PROTOCOL_ERROR", "Bad Request")).await;
        return None;
    }
    let xsig = match auth_frame.header2("X-Sig", "sig") {
        Some(s) => s.to_string(),
        None => {
            let _ = send_frame(sender, &error_response(400, "Bad Request")).await;
            return None;
        }
    };

    // Decode X-Sig from base64 → bytes → hex (verify_agent_signature takes hex)
    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&xsig) {
        Ok(b) => b,
        Err(_) => {
            let _ = send_frame(sender, &error_response(400, "Bad Request")).await;
            return None;
        }
    };
    let sig_hex = hex::encode(&sig_bytes);

    // Consume nonce — retrieves stored canonical payload; None means expired/unknown.
    let payload = match state.broker.nonce_store.consume(&nonce_hex) {
        Some(p) => p,
        None => {
            tracing::warn!("Stale nonce for {}@{}", name, project);
            let _ = send_frame(sender, &error_response_with_code(401, "AUTH_STALE", "Unauthorized")).await;
            return None;
        }
    };

    // Verify — verify_strict rejects malleable signatures.
    match crate::identity::verify_agent_signature(&pubkey_hex, &payload, &sig_hex) {
        Ok(()) => {
            tracing::info!("Ed25519 auth: {}@{} authenticated", name, project);
            Some((name, project))
        }
        Err(_) => {
            tracing::warn!("Bad signature from {}@{}", name, project);
            let _ = send_frame(sender, &error_response_with_code(401, "AUTH_WRONG_KEY", "Unauthorized")).await;
            None
        }
    }
}

// ── Connection lifecycle ──────────────────────────────────────────────────────

async fn handle_connection(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    let (name, project) = match wait_for_handshake(&mut sender, &mut receiver, &state).await {
        Some(info) => info,
        None => return, // error already sent in wait_for_handshake
    };

    // Register live session — 409 Conflict if same identity already connected.
    let mut rx = match state.broker.connect(&name, &project).await {
        Ok(rx) => rx,
        Err(()) => {
            let _ = send_frame(&mut sender, &error_response_with_code(409, "CONFLICT", "Conflict")).await;
            return;
        }
    };

    // Drain pending messages stored while agent was offline.
    let pending = state.delivery.drain_pending(&name, &project);
    let pending_count = pending.len();

    // Send 200 OK — session is open.
    let session_id = uuid::Uuid::new_v4().to_string();
    let ok_frame = HttpFrame::response(200, "OK")
        .add_header("X-Session-Id", &session_id)
        .add_header("X-Pending-Count", &pending_count.to_string())
        .finalize();
    if !send_frame(&mut sender, &ok_frame).await {
        state.broker.disconnect(&name, &project).await;
        return;
    }

    // Send each pending DELIVER frame and mark it delivered after each successful write.
    // drain_pending marks rows 'sending' — we transition them to 'delivered' here so a
    // WS drop mid-drain causes 'sending' rows to be re-drained on reconnect (no silent loss).
    for msg in pending {
        if sender.send(Message::Text(msg.body.clone().into())).await.is_ok() {
            state.delivery.mark_delivered(&msg.id, &name, &project);
        } else {
            state.broker.disconnect(&name, &project).await;
            return;
        }
    }

    // mpsc channel: recv_task sends response frames back to send_task for client delivery.
    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel::<String>(8);

    // Send task: forward live messages and response frames to the client.
    let mut send_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = rx.recv() => match result {
                    Ok(msg) => {
                        if sender.send(Message::Text(msg.into())).await.is_err() {
                            tracing::warn!("WS send error — send_task exiting");
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("send_task: receiver lagged, skipped {} messages", n);
                        continue; // recoverable — receiver advances past skipped messages
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                Some(resp) = resp_rx.recv() => {
                    if sender.send(Message::Text(resp.into())).await.is_err() {
                        tracing::warn!("WS send error on response frame — send_task exiting");
                        break;
                    }
                }
            }
        }
    });

    let state_for_recv = state.clone();
    let rate_limiter = state.rate_limiter.clone();
    let agent_name = name.clone();
    let agent_project = project.clone();

    // Receive task: parse inbound HttpFrames and dispatch.
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // Parse first — Resp frames (relay responses from Boards) must bypass
                    // rate limiting since they are broker-internal, not client-initiated.
                    let frame = match http_frame::parse(&text) {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::warn!("HttpFrame parse error from {}@{}: {}", agent_name, agent_project, e);
                            let _ = resp_tx.try_send(
                                error_response_with_code(400, "PARSE_ERROR", "Bad Request").serialize(),
                            );
                            continue;
                        }
                    };
                    // Rate-limit per project — same bucket as HTTP write-path routes.
                    // Resp frames from Boards bypass this check — they are relay responses,
                    // not client-initiated traffic. Any other sender must pass the check
                    // regardless of frame shape (no throttle-bypass lane for non-Boards).
                    if !(frame.is_response() && agent_name == "Boards") && !rate_limiter.check(&agent_project) {
                        tracing::debug!("WS rate limit exceeded for project '{}'", agent_project);
                        let _ = resp_tx.try_send(error_response(429, "Too Many Requests").serialize());
                        continue;
                    }
                    handle_inbound(frame, &agent_name, &agent_project, &state_for_recv, &resp_tx).await;
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => { recv_task.abort(); }
        _ = &mut recv_task => { send_task.abort(); }
    }

    state.broker.disconnect(&name, &project).await;
    tracing::info!("WebSocket closed: {}@{}", name, project);
}

// ── Inbound frame dispatch ────────────────────────────────────────────────────

/// Dispatch a verified inbound frame from an authenticated connection.
/// Handles: Resp frames from Boards (relay back to source), POST /v1/posts|reactions
/// (→ Boards via relay), POST /v1/dms (broker-direct), PUBLISH <any-path>
/// (Boards→agents), PUT /v1/presence.
/// Sends a response frame via resp_tx on completion.
async fn handle_inbound(
    mut frame: HttpFrame,
    name: &str,
    project: &str,
    state: &Arc<AppState>,
    resp_tx: &tokio::sync::mpsc::Sender<String>,
) {
    // Resp frames from Boards: relay back to source via relay_map lookup.
    // Must be checked before the verb/path match — Resp frames have no verb.
    // Guard: only Boards is authorized to send Resp frames. A non-Boards sender
    // that emits a response-shaped frame is already rate-limited by recv_task;
    // reject here to prevent relay-map access and relay-id spoofing.
    if frame.is_response() {
        // Log relay responses before any early-return path.
        log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "(relay response)");
        if name != "Boards" {
            tracing::warn!("Resp-shaped frame from non-Boards sender {}@{} — rejected", name, project);
            let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
            return;
        }
        let relay_id = frame.header("correlation-id").map(|s| s.to_string());
        if let Some(ref rid) = relay_id {
            if rid.starts_with("r-") {
                if let Some((_, entry)) = state.relay_map.remove(rid) {
                    // Rewrite correlation-id back to source's original (or remove if source had none).
                    match entry.source_correlation_id {
                        Some(ref cid) => frame.set_header("correlation-id", cid),
                        None => frame.remove_header("correlation-id"),
                    }
                    // Bounded send: timeout prevents head-of-line blocking if source's queue
                    // (8 slots) is full. Entry is already removed — timeout task is dead — so
                    // we must cap this ourselves.
                    match tokio::time::timeout(
                        state.config.relay_timeout,
                        entry.resp_tx.send(frame.serialize()),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) => {
                            tracing::debug!(
                                "relay: source disconnected before Boards Resp for relay-id {} — dropped",
                                rid
                            );
                        }
                        Err(_) => {
                            tracing::warn!(
                                "relay: resp_tx backpressure timeout for relay-id {} — dropped",
                                rid
                            );
                        }
                    }
                } else {
                    tracing::warn!("Resp from {}@{}: unknown relay-id '{}' — dropping", name, project, rid);
                }
                return;
            }
        }
        // Resp with no relay-id or non-relay correlation-id — unexpected, drop.
        tracing::warn!("Unexpected Resp from {}@{} — dropping", name, project);
        return;
    }

    // Extract correlation-id once so every locally-generated response can echo it back.
    // The CLI uses cid to match responses to requests — missing cid causes 8s timeouts.
    let source_cid = frame.header("correlation-id").map(|s| s.to_string());
    let reply = |mut r: HttpFrame| -> String {
        if let Some(ref cid) = source_cid {
            r.set_header("correlation-id", cid);
        }
        r.serialize()
    };

    let verb = frame.verb().unwrap_or("").to_string();
    let path = frame.path().unwrap_or("").to_string();

    match (verb.as_str(), path.as_str()) {
        ("POST", "/v1/posts") | ("POST", "/v1/reactions") => {
            let xto = match frame.header2("X-To", "to").map(|s| s.to_string()) {
                Some(v) => v,
                None => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (missing to:)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            let channel_project = match http_frame::parse_channel(&xto) {
                Ok((_, p)) => p.to_string(),
                Err(_) => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (invalid channel)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            // Canonicalize X-From to the authenticated session identity (spec §5).
            // Prevents agents from forging a different sender identity to Boards.
            // Also strips any v2 `from:` header so exactly one identity header survives.
            log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ relayed (async)");
            frame.set_canonical_from(&format!("{}@{}", name, project));
            let relay_timeout = state.config.relay_timeout;
            forward_to_boards(frame, &channel_project, &state.broker, &state.relay_map, resp_tx, relay_timeout, &state.wire_log).await;
        }
        ("POST", "/v1/dms") => {
            // Broker-direct DM delivery — no Boards dependency on the hot path (spec §5).
            let xto = match frame.header2("X-To", "to").map(|s| s.to_string()) {
                Some(v) => v,
                None => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (missing to:)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            let (recv_name, recv_project) = match http_frame::parse_identity(&xto) {
                Ok((n, p)) => (n.to_string(), p.to_string()),
                Err(_) => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (invalid identity)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ DM routing");
            let deliver_path = format!("/agents/{}@{}/dms", recv_name, recv_project);
            deliver_dm_frame(frame, recv_name, recv_project, xto, &deliver_path, name, project, source_cid.clone(), state, resp_tx).await;
        }
        // C6: agent-addressed resource paths — POST /agents/<name>@<project>/dms delivers as DM.
        // Recipient is extracted from the path; no X-To required. Delivery logic is identical
        // to the v1 /v1/dms arm (both delegate to deliver_dm_frame).
        ("POST", p) if p.starts_with("/agents/") => {
            let (recv_name, recv_project) = match http_frame::parse_identity_from_path(p) {
                Some((n, pr)) => (n.to_string(), pr.to_string()),
                None => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (invalid agent path)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            let xto = format!("{}@{}", recv_name, recv_project);
            log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ DM routing (C6)");
            deliver_dm_frame(frame, recv_name, recv_project, xto, p, name, project, source_cid.clone(), state, resp_tx).await;
        }
        ("PUBLISH", _) => {
            // Boards-only verb — reject from regular agents.
            // Path is informational (forwarded as-is in DELIVER frames); routing is entirely from
            // mentions: list. Accept any path so C6 resource paths (e.g. /channels/<c>@<p>/...) work.
            if name != "Boards" {
                tracing::warn!("PUBLISH rejected from non-Boards agent {}@{}", name, project);
                log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 403 forbidden");
                let _ = resp_tx.try_send(reply(error_response(403, "Forbidden")));
                return;
            }

            // Guard: if the path starts with /channels/, validate it parses correctly.
            // A malformed segment like `/channels/@project/...` (empty channel name) must be
            // rejected — `parse_channel_from_path` returns None for empty channel or project.
            if path.starts_with("/channels/") && http_frame::parse_channel_from_path(&path).is_none() {
                tracing::warn!("PUBLISH from Boards@{}: malformed channel path '{}' — 400", project, path);
                log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (malformed channel path)");
                let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                return;
            }

            // C13: broker trusts the pre-resolved mentions: list from Boards.
            // No validation — Boards resolves recipients; broker just fans out.
            // mentions: absent → 400 (no X-To fallback — binary swap is gated on Lisa's cutover).
            let recipients: Vec<String> = if let Some(mentions) = frame.header2("mentions", "X-Mentions").map(|s| s.to_string()) {
                mentions.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
            } else {
                log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (no mentions)");
                let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                return;
            };

            if recipients.is_empty() {
                tracing::warn!("PUBLISH from {}@{}: empty recipient list — dropping", name, project);
                log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (empty recipients)");
                let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                return;
            }

            let _ = resp_tx.try_send(reply(HttpFrame::response(200, "OK").finalize()));
            // MUST NOT block the recv loop — spawn fan-out.
            // wire_log_clone is cloned here and moved into the spawn — confirmed correct.
            let broker_clone = state.broker.clone();
            let wire_log_clone = state.wire_log.clone();
            log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ fan-out (async)");
            tokio::spawn(async move {
                fan_out_publish(frame, recipients, &broker_clone, wire_log_clone).await;
            });
        }
        ("PUT", "/v1/presence") => {
            let status = match frame.header2("X-Status", "status").map(|s| s.to_string()) {
                Some(s) => s,
                None => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (missing status)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            let agent_state = match status.as_str() {
                "available" => AgentState::Available,
                "busy" => AgentState::Busy,
                "offline" => AgentState::Offline,
                _ => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (invalid status)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            state.broker.set_state(name, project, agent_state).await;
            log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ presence update");
            let _ = resp_tx.try_send(reply(HttpFrame::response(200, "OK").finalize()));
        }
        // C6: channel-rooted resource paths — any POST to /channels/<channel>@<project>/...
        // is forwarded to Boards@project. Broker extracts the project from the path; no X-To
        // required (path is the canonical address). X-From is canonicalized as usual.
        ("POST", p) if p.starts_with("/channels/") => {
            let channel_project = match http_frame::parse_channel_from_path(p) {
                Some((_, proj)) => proj.to_string(),
                None => {
                    log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (invalid channel path)");
                    let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
                    return;
                }
            };
            log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ relayed (async)");
            frame.set_canonical_from(&format!("{}@{}", name, project));
            let relay_timeout = state.config.relay_timeout;
            forward_to_boards(frame, &channel_project, &state.broker, &state.relay_map, resp_tx, relay_timeout, &state.wire_log).await;
        }
        _ => {
            tracing::warn!("Unknown verb/path from {}@{}: {} {}", name, project, verb, path);
            log_wire(&state.wire_log, "[INBOUND]", &frame.serialize(), "→ 400 bad request (unknown verb/path)");
            let _ = resp_tx.try_send(reply(error_response(400, "Bad Request")));
        }
    }
}

/// Deliver a DM frame to its recipient. Shared by both the v1 (`/v1/dms`) and C6
/// (`/agents/<name>@<project>/dms`) match arms.
///
/// - Canonicalizes X-From to authenticated sender identity.
/// - Unknown recipient → 404.
/// - Live recipient → DELIVER + 200.
/// - Offline recipient → store_pending + 202.
/// - Optional archive fan-out to Boards (best-effort, non-blocking).
///
/// AUDIT(C13-Q6): DELIVER body is `frame.body` (application content), NOT the full
/// inbound wire frame bytes nested as an opaque blob. Safe.
#[allow(clippy::too_many_arguments)]
async fn deliver_dm_frame(
    mut frame: HttpFrame,
    recv_name: String,
    recv_project: String,
    xto: String,
    source_path: &str,
    sender_name: &str,
    sender_project: &str,
    source_cid: Option<String>,
    state: &Arc<AppState>,
    resp_tx: &tokio::sync::mpsc::Sender<String>,
) {
    let reply = |mut r: HttpFrame| -> String {
        if let Some(ref cid) = source_cid {
            r.set_header("correlation-id", cid);
        }
        r.serialize()
    };

    // Canonicalize X-From to the authenticated session identity (spec §5).
    // Also strips any v2 `from:` header so exactly one identity header survives.
    let sender_identity = format!("{}@{}", sender_name, sender_project);
    frame.set_canonical_from(&sender_identity);

    // Unknown recipient → 404.
    if !state.broker.repo.agent_exists(&recv_name, &recv_project) {
        let _ = resp_tx.try_send(reply(error_response(404, "Not Found")));
        return;
    }

    // Build DELIVER frame: verb=DELIVER, path is always C6 resource form (/agents/<n>@<p>/dms),
    // inner_verb=POST (C7), has_version=false (compact v2, no HTTP/1.1 suffix).
    // Only `from:` header on broker-emitted DM DELIVER — no redundant addressing headers.
    // Recipient addressed by direct WS session send; path always carries recipient identity.
    // v1 callers (POST /v1/dms) are canonicalized to C6 path before reaching here.
    let mut deliver = HttpFrame {
        first_line: FirstLine::Request {
            verb: "DELIVER".to_string(),
            inner_verb: Some("POST".to_string()),
            path: source_path.to_string(),
            has_version: false,
        },
        headers: Vec::new(),
        body: String::new(),
    };
    deliver = deliver
        .add_header("from", &sender_identity);
    deliver.body = frame.body.clone();
    let deliver = deliver.finalize();

    tracing::debug!(
        "DELIVER {} → {}: from={} to={}",
        source_path,
        recv_name,
        sender_identity,
        xto
    );

    // Serialize once — reused for live send, store_pending, and wire log (ground truth).
    let serialized_deliver = deliver.serialize();
    // Attempt live delivery.
    let delivered = state.broker.send_to_agent(&recv_name, &recv_project, &serialized_deliver).await;
    if delivered {
        log_wire(&state.wire_log, "[OUTBOUND]", &serialized_deliver, &format!("delivered live to {}@{}", recv_name, recv_project));
        let _ = resp_tx.try_send(reply(HttpFrame::response(200, "OK").finalize()));

        // Best-effort archive fan-out — Boards offline must NOT block delivery.
        if state.config.archive_dms {
            let archive_broker = state.broker.clone();
            let archive_path = format!("/agents/{}@{}/dms", recv_name, recv_project);
            let mut archive = HttpFrame::request("POST", &archive_path)
                .add_header("from", &sender_identity)
                .add_header("to", &xto);
            archive.body = frame.body.clone();
            let archive = archive.finalize();
            let recv_project_clone = recv_project.clone();
            tokio::spawn(async move {
                let sent = archive_broker
                    .send_to_agent("Boards", &recv_project_clone, &archive.serialize())
                    .await;
                if !sent {
                    tracing::debug!(
                        "DM archive: Boards@{} not connected — drop",
                        recv_project_clone
                    );
                }
            });
        }
    } else {
        // Recipient offline — store for drain on reconnect.
        match state.delivery.store_pending(
            &recv_name,
            &recv_project,
            sender_name,
            sender_project,
            &serialized_deliver,
        ) {
            Ok(()) => {
                log_wire(&state.wire_log, "[OUTBOUND]", &serialized_deliver, &format!("stored pending → {}@{}", recv_name, recv_project));
                let _ = resp_tx.try_send(reply(HttpFrame::response(202, "Accepted").finalize()));
            }
            Err(e) => {
                tracing::warn!(
                    "DM store_pending failed for {}@{}: {}",
                    recv_name,
                    recv_project,
                    e
                );
                let _ = resp_tx.try_send(reply(error_response(503, "Service Unavailable")));
            }
        }
    }
}

/// Forward a POST frame to Boards@target_project, inserting a relay entry so Boards'
/// Resp can be routed back to the source connection.
///
/// Protocol (Q7):
/// 1. Generate relay-id `r-<uuid>`; replace source's `correlation-id` with it on the outbound frame.
///    Boards echoes the `correlation-id` back on its Resp — broker uses it to find this entry.
/// 2. Insert RelayEntry BEFORE calling send_to_agent — closes the TOCTOU window where a very
///    fast Boards Resp could arrive before the entry is registered (→ unknown relay-id drop).
/// 3. If Boards not connected: remove the entry, return 503 immediately.
/// 4. Spawn timeout task to fire 504 if Boards doesn't reply within relay_timeout.
///
/// On source disconnect before Boards replies: `entry.resp_tx.send().await` returns Err
/// (channel closed) — logged at debug level, no further action needed.
async fn forward_to_boards(
    mut frame: HttpFrame,
    target_project: &str,
    broker: &Arc<BrokerState>,
    relay_map: &crate::api::routes::RelayMap,
    resp_tx: &tokio::sync::mpsc::Sender<String>,
    relay_timeout: std::time::Duration,
    wire_log: &Option<Arc<SyncSender<String>>>,
) {
    use crate::api::routes::RelayEntry;

    let source_correlation_id = frame.header("correlation-id").map(|s| s.to_string());
    let relay_id = format!("r-{}", Uuid::new_v4());

    // Replace source's correlation-id with relay-id so Boards echoes it back on Resp.
    frame.set_header("correlation-id", &relay_id);

    // Register BEFORE sending — closes the TOCTOU window.
    relay_map.insert(
        relay_id.clone(),
        RelayEntry {
            resp_tx: resp_tx.clone(),
            source_correlation_id: source_correlation_id.clone(),
        },
    );

    // Serialize once — used for both the send and the wire log (ground truth of bytes on wire).
    let serialized = frame.serialize();
    // AUDIT(C13-Q6): frame.serialize() sends headers + application body of the original request.
    // The body field is the raw application content the agent sent — NOT the full inbound wire
    // frame nested as an opaque blob. The broker re-serializes from the parsed HttpFrame struct,
    // so only the intended fields are forwarded. Safe.
    let delivered = broker.send_to_agent("Boards", target_project, &serialized).await;
    if !delivered {
        // Boards not connected — cancel relay entry, 503 immediately.
        relay_map.remove(&relay_id);
        tracing::warn!("Boards@{} not connected — 503", target_project);
        log_wire(wire_log, "[OUTBOUND]", &serialized, &format!("→ Boards@{} not connected — 503", target_project));
        let mut r = HttpFrame::response(503, "Service Unavailable").finalize();
        r.set_header("Retry-After", "1");
        if let Some(cid) = source_correlation_id {
            r.set_header("correlation-id", &cid);
        }
        let _ = resp_tx.try_send(r.serialize());
        return;
    }
    log_wire(wire_log, "[OUTBOUND]", &serialized, &format!("→ relayed to Boards@{}", target_project));

    // Timeout: if Boards doesn't respond within relay_timeout, fire a 504.
    let relay_map_clone = relay_map.clone();
    tokio::spawn(async move {
        tokio::time::sleep(relay_timeout).await;
        if let Some((_, entry)) = relay_map_clone.remove(&relay_id) {
            tracing::warn!("relay-id {} timed out — 504", relay_id);
            let mut r = HttpFrame::response(504, "Gateway Timeout").finalize();
            if let Some(cid) = entry.source_correlation_id {
                r.set_header("correlation-id", &cid);
            }
            // Source may have disconnected — log but don't panic.
            if entry.resp_tx.send(r.serialize()).await.is_err() {
                tracing::debug!("relay: source disconnected before timeout for relay-id {} — dropped", relay_id);
            }
        }
    });
}

/// Fan out a PUBLISH frame to a pre-resolved list of recipients (C13 mentions: list).
/// Sends a DELIVER frame (same headers and body, verb changed) to each connected recipient.
/// Live-only: drops delivery if recipient is not connected (no pending queue for DELIVER).
/// Broker trusts the list from Boards — no re-validation of recipient identities.
async fn fan_out_publish(frame: HttpFrame, recipients: Vec<String>, broker: &Arc<BrokerState>, wire_log: Option<Arc<SyncSender<String>>>) {
    for recipient in &recipients {
        let (recv_name, recv_project) = match http_frame::parse_identity(recipient) {
            Ok(r) => r,
            Err(_) => {
                // Should not happen — caller pre-validates — but be defensive.
                tracing::warn!("PUBLISH fan-out: invalid recipient '{}' (should have been filtered)", recipient);
                continue;
            }
        };

        // Clone PUBLISH frame and change verb+path to DELIVER for this recipient.
        // AUDIT(C13-Q6): deliver.body = frame.body (clone) — the application content from Boards.
        // NOT the full PUBLISH wire bytes nested as a body. The broker clones the parsed struct
        // and mutates verb/X-To only; path is preserved from the original PUBLISH (C6 or v1). Safe.
        let publish_path = frame.path().unwrap_or("/v1/deliveries").to_string();
        let publish_inner_verb = frame.inner_verb().map(str::to_string);
        let mut deliver = frame.clone();
        deliver.first_line = FirstLine::Request {
            verb: "DELIVER".to_string(),
            inner_verb: publish_inner_verb,
            path: publish_path,
            has_version: false, // broker-emitted frames use compact v2 form (no HTTP/1.1 suffix)
        };
        // v2-only headers on broker-emitted fan-out DELIVER.
        // `to:` identifies the individual recipient on the broadcast (retained — meaningful).
        // `from:` normalised from whichever form Boards sent (v1 X-From or v2 from:).
        // X-From and X-To stripped — broker-emitted frames use v2 only.
        deliver.set_header("to", recipient);
        deliver.remove_header("X-To");
        if let Some(sender) = deliver.header2("X-From", "from").map(str::to_string) {
            deliver.set_header("from", &sender);
        }
        deliver.remove_header("X-From");

        // Serialize once — reused for send and wire log (ground truth of bytes on wire).
        let serialized_deliver = deliver.serialize();
        let delivered = broker.send_to_agent(recv_name, recv_project, &serialized_deliver).await;
        if delivered {
            log_wire(&wire_log, "[OUTBOUND]", &serialized_deliver, recipient);
        } else {
            tracing::debug!(
                "DELIVER to {} not connected — dropping (live-only fan-out)",
                recipient
            );
        }
    }
}

#[cfg(test)]
#[path = "ws_auth_tests.rs"]
mod ws_auth_tests;

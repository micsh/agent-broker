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
use uuid::Uuid;

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
    while let Some(Ok(msg)) = receiver.next().await {
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

    let xfrom = match frame.header("X-From") {
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

    let xpubkey = frame.header("X-Pubkey").map(|s| s.to_string());

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
                        let provided = match frame.header("X-Registration-Token") {
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
    let xsig = match auth_frame.header("X-Sig") {
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

    // Send each pending message body as a raw text frame.
    for msg in pending {
        if sender.send(Message::Text(msg.body.into())).await.is_err() {
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
                    Err(_) => break,
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

    let broker = state.broker.clone();
    let rate_limiter = state.rate_limiter.clone();
    let agent_name = name.clone();
    let agent_project = project.clone();

    // Receive task: parse inbound HttpFrames and dispatch.
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // Rate-limit per project — same bucket as HTTP write-path routes.
                    if !rate_limiter.check(&agent_project) {
                        tracing::debug!("WS rate limit exceeded for project '{}'", agent_project);
                        let _ = resp_tx.try_send(error_response(429, "Too Many Requests").serialize());
                        continue;
                    }
                    match http_frame::parse(&text) {
                        Ok(frame) => {
                            handle_inbound(frame, &agent_name, &agent_project, &broker, &resp_tx).await;
                        }
                        Err(e) => {
                            tracing::warn!("HttpFrame parse error from {}@{}: {}", agent_name, agent_project, e);
                            let _ = resp_tx.try_send(
                                error_response_with_code(400, "PARSE_ERROR", "Bad Request").serialize(),
                            );
                        }
                    }
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
/// Handles: POST /v1/posts|reactions|dms (→ Boards), PUBLISH /v1/deliveries (Boards→agents),
/// PUT /v1/presence. Sends a response frame via resp_tx on completion.
async fn handle_inbound(
    mut frame: HttpFrame,
    name: &str,
    project: &str,
    broker: &Arc<BrokerState>,
    resp_tx: &tokio::sync::mpsc::Sender<String>,
) {
    let verb = frame.verb().unwrap_or("").to_string();
    let path = frame.path().unwrap_or("").to_string();

    match (verb.as_str(), path.as_str()) {
        ("POST", "/v1/posts") | ("POST", "/v1/reactions") => {
            let xto = match frame.header("X-To").map(|s| s.to_string()) {
                Some(v) => v,
                None => {
                    let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                    return;
                }
            };
            let channel_project = match http_frame::parse_channel(&xto) {
                Ok((_, p)) => p.to_string(),
                Err(_) => {
                    let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                    return;
                }
            };
            // Canonicalize X-From to the authenticated session identity (spec §5).
            // Prevents agents from forging a different sender identity to Boards.
            frame.set_header("X-From", &format!("{}@{}", name, project));
            forward_to_boards(frame, &channel_project, broker, resp_tx).await;
        }
        ("POST", "/v1/dms") => {
            let xto = match frame.header("X-To").map(|s| s.to_string()) {
                Some(v) => v,
                None => {
                    let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                    return;
                }
            };
            let recipient_project = match http_frame::parse_identity(&xto) {
                Ok((_, p)) => p.to_string(),
                Err(_) => {
                    let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                    return;
                }
            };
            // Canonicalize X-From to the authenticated session identity (spec §5).
            // Prevents agents from forging a different sender identity to Boards.
            frame.set_header("X-From", &format!("{}@{}", name, project));
            forward_to_boards(frame, &recipient_project, broker, resp_tx).await;
        }
        ("PUBLISH", "/v1/deliveries") => {
            // Boards-only verb — reject from regular agents.
            if name != "Boards" {
                tracing::warn!("PUBLISH rejected from non-Boards agent {}@{}", name, project);
                let _ = resp_tx.try_send(error_response(403, "Forbidden").serialize());
                return;
            }
            let xto = match frame.header("X-To").map(|s| s.to_string()) {
                Some(v) => v,
                None => {
                    let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                    return;
                }
            };
            // Validate all recipients in X-To are valid name@project identities (spec §9).
            if let Err(e) = http_frame::validate_xto_shape("PUBLISH", "/v1/deliveries", &xto) {
                tracing::warn!("PUBLISH X-To invalid from {}@{}: {}", name, project, e);
                let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                return;
            }
            // MUST NOT block the recv loop — spawn fan-out.
            let broker_clone = broker.clone();
            tokio::spawn(async move {
                fan_out_publish(frame, xto, &broker_clone).await;
            });
        }
        ("PUT", "/v1/presence") => {
            let status = match frame.header("X-Status").map(|s| s.to_string()) {
                Some(s) => s,
                None => {
                    let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                    return;
                }
            };
            let agent_state = match status.as_str() {
                "available" => AgentState::Available,
                "busy" => AgentState::Busy,
                "offline" => AgentState::Offline,
                _ => {
                    let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
                    return;
                }
            };
            broker.set_state(name, project, agent_state).await;
            let _ = resp_tx.try_send(HttpFrame::response(200, "OK").finalize().serialize());
        }
        _ => {
            tracing::warn!("Unknown verb/path from {}@{}: {} {}", name, project, verb, path);
            let _ = resp_tx.try_send(error_response(400, "Bad Request").serialize());
        }
    }
}

/// Forward a POST frame to Boards@target_project.
/// Responds 200 OK if delivered, 503 Service Unavailable (Retry-After: 1) if not connected.
async fn forward_to_boards(
    frame: HttpFrame,
    target_project: &str,
    broker: &Arc<BrokerState>,
    resp_tx: &tokio::sync::mpsc::Sender<String>,
) {
    let delivered = broker.send_to_agent("Boards", target_project, &frame.serialize()).await;
    let response = if delivered {
        HttpFrame::response(200, "OK").finalize()
    } else {
        tracing::warn!("Boards@{} not connected — 503", target_project);
        let mut r = HttpFrame::response(503, "Service Unavailable").finalize();
        r.set_header("Retry-After", "1");
        r
    };
    let _ = resp_tx.try_send(response.serialize());
}

/// Fan out a PUBLISH frame to each recipient in the comma-separated X-To list.
/// Sends a DELIVER frame (same headers, verb changed) to each connected recipient.
/// Live-only: drops delivery if recipient is not connected (no pending queue for DELIVER).
async fn fan_out_publish(frame: HttpFrame, xto: String, broker: &Arc<BrokerState>) {
    for recipient in xto.split(',') {
        let recipient = recipient.trim();
        if recipient.is_empty() {
            continue;
        }
        let (recv_name, recv_project) = match http_frame::parse_identity(recipient) {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!("PUBLISH fan-out: invalid recipient '{}'", recipient);
                continue;
            }
        };

        // Clone PUBLISH frame and change verb+path to DELIVER; replace X-To with single recipient.
        let mut deliver = frame.clone();
        deliver.first_line = FirstLine::Request {
            verb: "DELIVER".to_string(),
            path: "/v1/deliveries".to_string(),
        };
        deliver.set_header("X-To", recipient);

        let delivered = broker.send_to_agent(recv_name, recv_project, &deliver.serialize()).await;
        if !delivered {
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

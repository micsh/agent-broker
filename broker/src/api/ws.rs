use crate::broker::state::BrokerState;
use crate::broker::{DeliveryEngine, dispatch_stanza};
use crate::api::routes::AppState;
use crate::stanza;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::stream::StreamExt;
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub async fn handle_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, state))
}

/// JSON envelopes for the WebSocket control plane.
/// After Connected handshake, all data is raw stanza XML.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEnvelope {
    /// Legacy: Client → Broker: authenticate with project key.
    /// Deprecated — agents should register a public key and use Hello.
    Connect {
        name: String,
        project: String,
        project_key: String,
    },
    /// New: Client → Broker: initiate Ed25519 challenge-response handshake.
    Hello {
        name: String,
        project: String,
    },
    /// Broker → Client: challenge bytes for Ed25519 signing.
    Challenge {
        /// 32-byte nonce as lowercase hex string.
        nonce: String,
        /// Unix timestamp (seconds) when challenge was issued. Client includes in signed payload.
        timestamp: u64,
        /// Connection-scoped session UUID. Included in signed payload.
        session_id: String,
    },
    /// New: Client → Broker: signed challenge response.
    Auth {
        /// Ed25519 signature over canonical payload as lowercase hex string.
        signature: String,
    },
    /// Broker → Client: auth success + pending count.
    Connected {
        session_id: String,
        pending_count: usize,
    },
    /// Broker → Client: error notification.
    Error {
        message: String,
        /// Structured error code for machine-readable handling. None for non-auth errors.
        /// AUTH_WRONG_KEY  — wrong private key (config error).
        /// AUTH_STALE      — nonce expired or clock skew (retry).
        /// AUTH_INVALID_CREDS — project key wrong or agent not found.
        #[serde(skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
    },
}

async fn handle_connection(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    let (name, project, session_id) = match wait_for_connect(&mut sender, &mut receiver, &state).await {
        Some(info) => info,
        None => return, // error already sent inside auth helpers
    };

    // Register live connection FIRST — so messages arriving during pending drain are buffered in rx
    let mut rx = state.broker.connect(&name, &project).await;

    // Drain pending messages — each body is raw stanza XML
    let pending = state.delivery.drain_pending(&name, &project);
    let pending_count = pending.len();

    let connected = WsEnvelope::Connected {
        session_id: session_id.clone(),
        pending_count,
    };
    if sender.send(Message::Text(serde_json::to_string(&connected).unwrap().into())).await.is_err() {
        return;
    }

    // Send each pending message as a raw stanza XML frame
    for msg in pending {
        if sender.send(Message::Text(msg.body.into())).await.is_err() {
            return;
        }
    }

    // mpsc channel: recv_task sends error frames back to send_task for delivery to client
    let (err_tx, mut err_rx) = tokio::sync::mpsc::channel::<String>(8);

    // Forward live messages and error frames to the client
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
                Some(err_msg) = err_rx.recv() => {
                    if sender.send(Message::Text(err_msg.into())).await.is_err() {
                        tracing::warn!("WS send error on error frame — send_task exiting");
                        break;
                    }
                }
            }
        }
    });

    let broker = state.broker.clone();
    let delivery = state.delivery.clone();
    let rate_limiter = state.rate_limiter.clone();
    let agent_name = name.clone();
    let agent_project = project.clone();

    // Receive stanza XML from client
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // Rate-limit per project — same bucket as HTTP write-path routes.
                    // Drop the stanza and send an error frame; keep the connection alive.
                    if !rate_limiter.check(&agent_project) {
                        tracing::debug!("WS rate limit exceeded for project '{}'", agent_project);
                        let msg = WsEnvelope::Error { message: "Rate limit exceeded".to_string(), error_code: None };
                        let _ = err_tx.try_send(serde_json::to_string(&msg).unwrap_or_default());
                        continue;
                    }
                    handle_stanza(&text, &agent_name, &agent_project, &broker, &delivery, &err_tx).await;
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
    tracing::info!("WebSocket closed: {}.{}", name, project);
}

/// Authenticate the WebSocket client. Handles both Ed25519 (Hello→Challenge→Auth) and
/// legacy project-key (Connect) flows. Returns (name, project, session_id) on success.
/// Sends Challenge (Ed25519 path) or Error frames directly via sender.
async fn wait_for_connect(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    receiver: &mut futures::stream::SplitStream<WebSocket>,
    state: &Arc<AppState>,
) -> Option<(String, String, String)> {
    let text = recv_text(receiver).await?;
    match serde_json::from_str::<WsEnvelope>(&text).ok()? {
        WsEnvelope::Hello { name, project } => {
            handle_hello_auth(sender, receiver, state, name, project).await
        }
        WsEnvelope::Connect { name, project, project_key } => {
            handle_legacy_auth(sender, state, name, project, project_key).await
        }
        _ => {
            // Unexpected envelope type — client sent something that isn't Hello or Connect.
            // Send a structured error so the client can distinguish protocol violations from drops.
            let _ = send_envelope(sender, &WsEnvelope::Error {
                message: "Expected Hello or Connect envelope to initiate connection".to_string(),
                error_code: Some("PROTOCOL_ERROR".to_string()),
            }).await;
            None
        }
    }
}

/// Receive a single Text message from the WS stream. Returns None on close or non-text.
async fn recv_text(receiver: &mut futures::stream::SplitStream<WebSocket>) -> Option<String> {
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(t) => return Some(t.to_string()),
            Message::Close(_) => return None,
            _ => continue,
        }
    }
    None
}

/// Send a WsEnvelope frame via the sender. Returns false if serialization or send failed.
async fn send_envelope(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    env: &WsEnvelope,
) -> bool {
    match serde_json::to_string(env) {
        Ok(json) => sender.send(Message::Text(json.into())).await.is_ok(),
        Err(_) => false,
    }
}

/// Ed25519 challenge-response path. Called when client sends Hello.
async fn handle_hello_auth(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    receiver: &mut futures::stream::SplitStream<WebSocket>,
    state: &Arc<AppState>,
    name: String,
    project: String,
) -> Option<(String, String, String)> {
    // Agent must exist
    if !state.broker.repo.agent_exists(&name, &project) {
        tracing::warn!("Hello from unregistered agent {}.{}", name, project);
        let _ = send_envelope(sender, &WsEnvelope::Error {
            message: "Agent not registered".to_string(),
            error_code: Some("AUTH_INVALID_CREDS".to_string()),
        }).await;
        return None;
    }

    // Must have a public key — no silent fallback within the Hello path
    let pubkey_hex = match state.broker.repo.get_agent_public_key(&name, &project) {
        Some(k) => k,
        None => {
            tracing::warn!(
                "Hello from {}.{} — no public key registered. Use Connect for project-key auth.",
                name, project
            );
            let _ = send_envelope(sender, &WsEnvelope::Error {
                message: "No public key registered — use project-key auth (Connect)".to_string(),
                error_code: Some("AUTH_INVALID_CREDS".to_string()),
            }).await;
            return None;
        }
    };

    // Issue challenge
    let session_id = uuid::Uuid::new_v4().to_string();
    let (nonce_bytes, _payload, timestamp) = state.broker.nonce_store.issue(&session_id, &name, &project);
    let nonce_hex = hex::encode(nonce_bytes);

    if !send_envelope(sender, &WsEnvelope::Challenge {
        nonce: nonce_hex.clone(),
        timestamp,
        session_id: session_id.clone(),
    }).await {
        return None;
    }

    // Receive Auth response
    let auth_text = recv_text(receiver).await?;
    let signature_hex = match serde_json::from_str::<WsEnvelope>(&auth_text).ok()? {
        WsEnvelope::Auth { signature } => signature,
        _ => return None,
    };

    // Consume nonce — retrieves stored canonical payload; None means expired
    let payload = match state.broker.nonce_store.consume(&nonce_hex) {
        Some(p) => p,
        None => {
            tracing::warn!("Stale nonce from {}.{}", name, project);
            let _ = send_envelope(sender, &WsEnvelope::Error {
                message: "Challenge expired — reconnect and retry".to_string(),
                error_code: Some("AUTH_STALE".to_string()),
            }).await;
            return None;
        }
    };

    // Verify signature
    match crate::identity::verify_agent_signature(&pubkey_hex, &payload, &signature_hex) {
        Ok(()) => {
            tracing::info!("Ed25519 auth: {}.{} authenticated", name, project);
            Some((name, project, session_id))
        }
        Err(_) => {
            tracing::warn!("Bad signature from {}.{}", name, project);
            let _ = send_envelope(sender, &WsEnvelope::Error {
                message: "Signature verification failed — wrong private key".to_string(),
                error_code: Some("AUTH_WRONG_KEY".to_string()),
            }).await;
            None
        }
    }
}

/// Legacy project-key path. Called when client sends Connect.
async fn handle_legacy_auth(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    state: &Arc<AppState>,
    name: String,
    project: String,
    project_key: String,
) -> Option<(String, String, String)> {
    tracing::warn!(
        "Deprecated project-key WS auth for {}.{} — register a public key via POST /agents/register",
        name, project
    );
    if let Err(reason) = state.broker.authenticate(&name, &project, &project_key) {
        tracing::warn!("Legacy auth failed for {}.{}: {}", name, project, reason);
        let _ = send_envelope(sender, &WsEnvelope::Error {
            message: reason,
            error_code: Some("AUTH_INVALID_CREDS".to_string()),
        }).await;
        return None;
    }
    let session_id = uuid::Uuid::new_v4().to_string();
    tracing::info!("WS connected (legacy auth): {}.{}", name, project);
    Some((name, project, session_id))
}

/// Handle an incoming stanza from an authenticated WebSocket client.
/// Sends WsEnvelope::Error frames back via err_tx on parse failure or identity mismatch.
async fn handle_stanza(
    text: &str,
    agent_name: &str,
    agent_project: &str,
    broker: &Arc<BrokerState>,
    delivery: &Arc<DeliveryEngine>,
    err_tx: &tokio::sync::mpsc::Sender<String>,
) {
    let parsed = match stanza::parse(text) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Invalid stanza from {}.{}: {}", agent_name, agent_project, e);
            let msg = WsEnvelope::Error { message: format!("Invalid stanza: {e}"), error_code: None };
            let _ = err_tx.try_send(serde_json::to_string(&msg).unwrap_or_default());
            return;
        }
    };

    // Accept both 'Name' and 'Name.Project' — reject only true spoofing
    let stanza_from = match &parsed {
        stanza::Stanza::Message(msg) => msg.from.as_str(),
        stanza::Stanza::Presence(p) => p.from.as_str(),
    };
    let (stanza_name, _) = stanza::resolve_agent_name(stanza_from, agent_project);
    if stanza_name != agent_name {
        tracing::warn!(
            "Stanza 'from' mismatch: stanza says '{}', authenticated as '{}'",
            stanza_from, agent_name
        );
        let msg = WsEnvelope::Error {
            message: "Stanza 'from' does not match authenticated identity".to_string(),
            error_code: None,
        };
        let _ = err_tx.try_send(serde_json::to_string(&msg).unwrap_or_default());
        return;
    }

    // WS dispatch doesn't validate target existence (broker stores for offline agents)
    if let Err(e) = dispatch_stanza(parsed, agent_project, broker, delivery, false).await {
        match e {
            crate::broker::DispatchError::DeliveryFailed(reason) => {
                tracing::error!("Delivery failed for {}.{}: {}", agent_name, agent_project, reason);
            }
            crate::broker::DispatchError::AmbiguousMention { name, projects } => {
                let msg = WsEnvelope::Error {
                    message: format!(
                        "Mention @{} is ambiguous: found in projects [{}]. Use Name.Project to disambiguate.",
                        name,
                        projects.join(", ")
                    ),
                    error_code: None,
                };
                let _ = err_tx.try_send(serde_json::to_string(&msg).unwrap_or_default());
            }
            _ => {}
        }
    }
}

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
/// After Connect/Connected handshake, all data is raw stanza XML.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsEnvelope {
    /// Client → Broker: authenticate with project key
    Connect {
        name: String,
        project: String,
        project_key: String,
    },
    /// Broker → Client: auth success + pending count
    Connected {
        session_id: String,
        pending_count: usize,
    },
    /// Broker → Client: error notification
    Error {
        message: String,
    },
}

async fn handle_connection(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    let (name, project, session_id) = match wait_for_connect(&mut receiver, &state).await {
        Some(info) => info,
        None => {
            let err = WsEnvelope::Error { message: "Authentication failed".to_string() };
            let _ = sender.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
            return;
        }
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
    let agent_name = name.clone();
    let agent_project = project.clone();

    // Receive stanza XML from client
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
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

async fn wait_for_connect(
    receiver: &mut futures::stream::SplitStream<WebSocket>,
    state: &Arc<AppState>,
) -> Option<(String, String, String)> {
    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg {
            if let Ok(WsEnvelope::Connect { name, project, project_key }) =
                serde_json::from_str::<WsEnvelope>(&text)
            {
                if let Err(reason) = state.broker.authenticate(&name, &project, &project_key) {
                    tracing::warn!("WS auth failed for {}.{}: {}", name, project, reason);
                    return None;
                }

                let session_id = uuid::Uuid::new_v4().to_string();
                tracing::info!("WS connected: {}.{}", name, project);
                return Some((name, project, session_id));
            }
        }
    }
    None
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
            let msg = WsEnvelope::Error { message: format!("Invalid stanza: {e}") };
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
            _ => {}
        }
    }
}

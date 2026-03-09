use crate::broker::state::BrokerState;
use crate::broker::DeliveryEngine;
use crate::api::routes::AppState;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use futures::stream::StreamExt;
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// WebSocket upgrade handler.
pub async fn handle_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_connection(socket, state))
}

/// Envelope for all WebSocket messages (both directions).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// Client → Broker: authenticate and register
    Connect {
        name: String,
        project: String,
        token: String,
    },
    /// Broker → Client: connection accepted
    Connected {
        session_id: String,
        pending_count: usize,
    },
    /// Client → Broker: update presence state
    Presence {
        state: crate::broker::state::AgentState,
    },
    /// Client → Broker: send a message
    Send {
        to_agent: Option<String>,
        to_channel: Option<String>,
        body: String,
        metadata: Option<String>,
    },
    /// Broker → Client: incoming message
    Message {
        id: String,
        from_agent: String,
        from_project: String,
        body: String,
        metadata: Option<String>,
    },
    /// Broker → Client: delivery of pending messages on connect
    Pending {
        messages: Vec<PendingItem>,
    },
    /// Broker → Client: error
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingItem {
    pub id: String,
    pub from_agent: String,
    pub from_project: String,
    pub body: String,
    pub metadata: Option<String>,
    pub created_utc: String,
}

async fn handle_connection(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Wait for Connect message
    let (name, project, session_id) = match wait_for_connect(&mut receiver, &state).await {
        Some(info) => info,
        None => return,
    };

    // Drain pending messages
    let pending = state.delivery.drain_pending(&name, &project).await;
    let pending_count = pending.len();

    // Send Connected acknowledgement
    let connected = WsMessage::Connected {
        session_id: session_id.clone(),
        pending_count,
    };
    if sender.send(Message::Text(serde_json::to_string(&connected).unwrap().into())).await.is_err() {
        return;
    }

    // Send pending messages
    if !pending.is_empty() {
        let items: Vec<PendingItem> = pending
            .into_iter()
            .map(|m| PendingItem {
                id: m.id,
                from_agent: m.from_agent,
                from_project: m.from_project,
                body: m.body,
                metadata: m.metadata,
                created_utc: m.created_utc,
            })
            .collect();
        let msg = WsMessage::Pending { messages: items };
        let _ = sender.send(Message::Text(serde_json::to_string(&msg).unwrap().into())).await;
    }

    // Subscribe to live messages via broadcast channel
    let mut rx: tokio::sync::broadcast::Receiver<String> = state.broker.connect(&name, &project, &session_id).await;

    // Spawn task to forward broadcast messages to WebSocket
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Process incoming WebSocket messages
    let broker = state.broker.clone();
    let delivery = state.delivery.clone();
    let agent_name = name.clone();
    let agent_project = project.clone();

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                        handle_client_message(&ws_msg, &agent_name, &agent_project, &broker, &delivery).await;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Wait for either task to finish (disconnect)
    tokio::select! {
        _ = &mut send_task => { recv_task.abort(); }
        _ = &mut recv_task => { send_task.abort(); }
    }

    // Clean up
    state.broker.disconnect(&name, &project).await;
    tracing::info!("WebSocket closed: {}.{}", name, project);
}

async fn wait_for_connect(
    receiver: &mut futures::stream::SplitStream<WebSocket>,
    state: &Arc<AppState>,
) -> Option<(String, String, String)> {
    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg {
            if let Ok(WsMessage::Connect { name, project, token }) =
                serde_json::from_str::<WsMessage>(&text)
            {
                // Verify token (simple check — agent must be registered)
                let valid = {
                    let conn = state.broker.db.conn();
                    let mut stmt = conn
                        .prepare("SELECT token FROM agents WHERE name = ?1 AND project = ?2")
                        .ok()?;
                    let stored_token: Option<String> = stmt
                        .query_row(rusqlite::params![name, project], |row: &rusqlite::Row| row.get(0))
                        .ok();
                    // Accept if no agent registered yet (first connect) or token matches
                    stored_token.is_none() || stored_token.as_deref() == Some(&token)
                };

                if valid {
                    let session_id = uuid::Uuid::new_v4().to_string();
                    return Some((name, project, session_id));
                }
            }
        }
    }
    None
}

async fn handle_client_message(
    msg: &WsMessage,
    name: &str,
    project: &str,
    broker: &Arc<BrokerState>,
    delivery: &Arc<DeliveryEngine>,
) {
    match msg {
        WsMessage::Presence { state } => {
            broker.set_state(name, project, *state).await;
        }
        WsMessage::Send {
            to_agent,
            to_channel,
            body,
            metadata,
        } => {
            let id = uuid::Uuid::new_v4().to_string();
            let _ = delivery
                .deliver(
                    &id,
                    name,
                    project,
                    to_agent.as_deref(),
                    to_channel.as_deref(),
                    body,
                    metadata.as_deref(),
                )
                .await;
        }
        _ => {}
    }
}

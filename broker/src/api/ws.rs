use crate::broker::state::{AgentState, BrokerState};
use crate::broker::DeliveryEngine;
use crate::api::routes::AppState;
use crate::stanza::{self, Stanza, Destination};
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

    // Register live connection — returns broadcast receiver
    let mut rx = state.broker.connect(&name, &project, &session_id).await;

    // Forward live messages (raw stanza XML from broadcast channel)
    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
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
                    handle_stanza(&text, &agent_name, &agent_project, &broker, &delivery).await;
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
                if !state.broker.repo.verify_project_key(&project, &project_key) {
                    tracing::warn!("WS auth failed: {}.{}", name, project);
                    return None;
                }

                if !state.broker.repo.agent_exists(&name, &project) {
                    tracing::warn!("WS connect from unregistered agent: {}.{}", name, project);
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
async fn handle_stanza(
    text: &str,
    agent_name: &str,
    agent_project: &str,
    broker: &Arc<BrokerState>,
    delivery: &Arc<DeliveryEngine>,
) {
    let stanza = match stanza::parse(text) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("Invalid stanza from {}.{}: {}", agent_name, agent_project, e);
            return;
        }
    };

    match stanza {
        Stanza::Message(msg) => {
            if msg.from != agent_name {
                tracing::warn!(
                    "Stanza 'from' mismatch: stanza says '{}', authenticated as '{}'",
                    msg.from, agent_name
                );
                return;
            }

            let id = uuid::Uuid::new_v4().to_string();
            let (to_agent, to_channel) = match stanza::resolve_destination(&msg.to) {
                Destination::Agent(a) => (Some(a), None),
                Destination::Channel(c) => (None, Some(c)),
            };

            if let Err(e) = delivery
                .deliver(
                    &id,
                    agent_name,
                    agent_project,
                    to_agent.as_deref(),
                    to_channel.as_deref(),
                    &msg.raw,
                    None,
                    &msg.mentions,
                )
                .await
            {
                tracing::error!("Delivery failed for {}.{}: {}", agent_name, agent_project, e);
            }
        }
        Stanza::Presence(p) => {
            if p.from != agent_name {
                tracing::warn!(
                    "Presence 'from' mismatch: stanza says '{}', authenticated as '{}'",
                    p.from, agent_name
                );
                return;
            }

            let agent_state = match p.status {
                stanza::PresenceStatus::Available => AgentState::Available,
                stanza::PresenceStatus::Busy => AgentState::Busy,
                stanza::PresenceStatus::Offline => AgentState::Offline,
            };
            broker.set_state(agent_name, agent_project, agent_state).await;
        }
    }
}

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
    /// Client → Broker: authenticate with project key
    Connect {
        name: String,
        project: String,
        project_key: String,
    },
    Connected {
        session_id: String,
        pending_count: usize,
    },
    Presence {
        state: crate::broker::state::AgentState,
    },
    Send {
        to_agent: Option<String>,
        to_channel: Option<String>,
        body: String,
        metadata: Option<String>,
    },
    Message {
        id: String,
        from_agent: String,
        from_project: String,
        body: String,
        metadata: Option<String>,
    },
    Pending {
        messages: Vec<PendingItem>,
    },
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

    let (name, project, session_id) = match wait_for_connect(&mut receiver, &state).await {
        Some(info) => info,
        None => {
            let err = WsMessage::Error { message: "Authentication failed".to_string() };
            let _ = sender.send(Message::Text(serde_json::to_string(&err).unwrap().into())).await;
            return;
        }
    };

    let pending = state.delivery.drain_pending(&name, &project);
    let pending_count = pending.len();

    let connected = WsMessage::Connected {
        session_id: session_id.clone(),
        pending_count,
    };
    if sender.send(Message::Text(serde_json::to_string(&connected).unwrap().into())).await.is_err() {
        return;
    }

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

    let mut rx = state.broker.connect(&name, &project, &session_id).await;

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
            if let Ok(WsMessage::Connect { name, project, project_key }) =
                serde_json::from_str::<WsMessage>(&text)
            {
                // Verify the project key
                if !state.broker.repo.verify_project_key(&project, &project_key) {
                    tracing::warn!("WS auth failed: {}.{}", name, project);
                    return None;
                }

                // Agent must be registered
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

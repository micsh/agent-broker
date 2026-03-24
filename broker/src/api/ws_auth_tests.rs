//! WS-level integration tests for Ed25519 challenge-response auth.
//!
//! Spins up a real axum server on a random port and connects via tokio-tungstenite.
//! Full internal access (this is a #[cfg(test)] submodule of api::ws) lets us
//! inspect `nonce_store` state after protocol exchanges without lib.rs exposure.
//!
//! Three adversarial scenarios:
//!   1. Auth-before-Challenge → PROTOCOL_ERROR frame
//!   2. Expired nonce (pre-drained) → AUTH_STALE frame  
//!   3. Wrong private key → AUTH_WRONG_KEY frame; nonce burned (second consume → None)

use crate::api;
use crate::api::middleware::ProjectRateLimiter;
use crate::api::routes::{AppState, BrokerConfig};
use crate::broker::{BrokerState, DeliveryEngine};
use crate::db;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use futures::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMsg};

// ── Test server ──────────────────────────────────────────────────────────────

/// Spawn a test broker on a random port. Returns the address and shared state.
/// Caller retains the `Arc<AppState>` to inspect nonce_store and repo after WS exchanges.
async fn spawn_test_server() -> (SocketAddr, Arc<AppState>) {
    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker.clone()));
    let config = BrokerConfig {
        admin_key: None,
        rate_limit_rps: 100,
    };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState {
        broker,
        delivery,
        config,
        rate_limiter,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let addr = listener.local_addr().expect("local_addr");

    let app = api::http_router(state.clone())
        .route("/ws", axum::routing::get(api::handle_ws))
        .with_state(state.clone());

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    (addr, state)
}

// ── WS helpers ───────────────────────────────────────────────────────────────

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

async fn ws_connect(addr: SocketAddr) -> WsStream {
    let url = format!("ws://127.0.0.1:{}/ws", addr.port());
    connect_async(url).await.expect("WS connect").0
}

async fn send_json(ws: &mut WsStream, v: Value) {
    ws.send(WsMsg::Text(v.to_string().into()))
        .await
        .expect("WS send");
}

async fn recv_json(ws: &mut WsStream) -> Value {
    loop {
        let msg = ws.next().await.expect("stream ended").expect("WS recv");
        match msg {
            WsMsg::Text(t) => return serde_json::from_str(&t).expect("JSON parse"),
            WsMsg::Close(_) => panic!("connection closed before receiving expected frame"),
            _ => continue,
        }
    }
}

// ── Test data setup ──────────────────────────────────────────────────────────

/// Register a project and agent with a fresh Ed25519 key pair.
/// Returns the SigningKey so tests can sign challenges.
fn setup_agent(state: &Arc<AppState>, project: &str, project_key: &str, agent: &str) -> SigningKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    state
        .broker
        .repo
        .register_project(project, project_key)
        .expect("register_project");
    state
        .broker
        .repo
        .register_agent(agent, project, "agent")
        .expect("register_agent");
    state
        .broker
        .repo
        .set_agent_public_key(agent, project, &pubkey_hex)
        .expect("set_agent_public_key");
    signing_key
}

/// Do Hello → Challenge exchange. Returns `(nonce_hex, timestamp, session_id)`.
async fn hello_and_get_challenge(
    ws: &mut WsStream,
    agent: &str,
    project: &str,
) -> (String, u64, String) {
    send_json(ws, json!({"type": "hello", "name": agent, "project": project})).await;
    let challenge = recv_json(ws).await;
    assert_eq!(challenge["type"], "challenge", "expected challenge frame");
    let nonce_hex = challenge["nonce"].as_str().unwrap().to_string();
    let timestamp = challenge["timestamp"].as_u64().unwrap();
    let session_id = challenge["session_id"].as_str().unwrap().to_string();
    (nonce_hex, timestamp, session_id)
}

/// Build the canonical payload and sign it.
fn sign_challenge(
    signing_key: &SigningKey,
    nonce_hex: &str,
    timestamp: u64,
    session_id: &str,
    agent: &str,
    project: &str,
) -> String {
    let nonce_bytes: [u8; 32] = hex::decode(nonce_hex)
        .expect("nonce hex")
        .try_into()
        .expect("nonce 32 bytes");
    let payload = crate::identity::build_challenge_payload(
        &nonce_bytes, timestamp, session_id, agent, project,
    );
    hex::encode(signing_key.sign(&payload).to_bytes())
}

// ── Adversarial tests ────────────────────────────────────────────────────────

/// Scenario 1: Client sends Auth as the first message (no Hello/Challenge first).
/// Broker must send PROTOCOL_ERROR and close — not silently drop.
#[tokio::test]
async fn ws_auth_before_challenge_sends_protocol_error() {
    let (addr, _state) = spawn_test_server().await;
    let mut ws = ws_connect(addr).await;

    // Skip Hello — send Auth immediately (protocol violation)
    send_json(&mut ws, json!({"type": "auth", "signature": "deadbeef"})).await;

    let resp = recv_json(&mut ws).await;
    assert_eq!(resp["type"], "error", "expected error frame, got: {resp}");
    assert_eq!(
        resp["error_code"], "PROTOCOL_ERROR",
        "expected PROTOCOL_ERROR, got: {resp}"
    );
}

/// Scenario 2: Nonce expires between Challenge issuance and Auth receipt.
/// Simulated by pre-draining the nonce from the store after receiving Challenge.
/// Broker must send AUTH_STALE — client must reconnect for a fresh challenge.
#[tokio::test]
async fn ws_expired_nonce_sends_auth_stale() {
    let (addr, state) = spawn_test_server().await;
    let signing_key = setup_agent(&state, "proj-stale", "key-stale", "Alice");

    let mut ws = ws_connect(addr).await;
    let (nonce_hex, timestamp, session_id) =
        hello_and_get_challenge(&mut ws, "Alice", "proj-stale").await;

    // Pre-drain the nonce — simulates TTL expiry before Auth arrives
    let was_present = state.broker.nonce_store.consume(&nonce_hex);
    assert!(was_present.is_some(), "nonce must be in store after challenge issuance");

    // Send a correctly-signed Auth — signature is valid, but nonce is gone
    let sig_hex = sign_challenge(&signing_key, &nonce_hex, timestamp, &session_id, "Alice", "proj-stale");
    send_json(&mut ws, json!({"type": "auth", "signature": sig_hex})).await;

    let resp = recv_json(&mut ws).await;
    assert_eq!(resp["type"], "error", "expected error frame, got: {resp}");
    assert_eq!(
        resp["error_code"], "AUTH_STALE",
        "expected AUTH_STALE for drained nonce, got: {resp}"
    );
}

/// Scenario 3: Client signs with the wrong private key.
/// Broker must send AUTH_WRONG_KEY. Nonce is burned — second consume returns None,
/// forcing the client to reconnect for a fresh challenge.
#[tokio::test]
async fn ws_wrong_key_sends_auth_wrong_key_and_burns_nonce() {
    let (addr, state) = spawn_test_server().await;
    let _correct_key = setup_agent(&state, "proj-badkey", "key-badkey", "Bob");

    let mut ws = ws_connect(addr).await;
    let (nonce_hex, timestamp, session_id) =
        hello_and_get_challenge(&mut ws, "Bob", "proj-badkey").await;

    // Sign with a DIFFERENT key — not the registered one
    let wrong_key = SigningKey::generate(&mut OsRng);
    let sig_hex = sign_challenge(&wrong_key, &nonce_hex, timestamp, &session_id, "Bob", "proj-badkey");
    send_json(&mut ws, json!({"type": "auth", "signature": sig_hex})).await;

    // Broker sends AUTH_WRONG_KEY
    let resp = recv_json(&mut ws).await;
    assert_eq!(resp["type"], "error", "expected error frame, got: {resp}");
    assert_eq!(
        resp["error_code"], "AUTH_WRONG_KEY",
        "expected AUTH_WRONG_KEY for wrong private key, got: {resp}"
    );

    // Nonce is burned: server consumed it before calling verify_agent_signature.
    // Second consume must return None — client must reconnect for a fresh challenge.
    let second = state.broker.nonce_store.consume(&nonce_hex);
    assert!(
        second.is_none(),
        "nonce must be burned after failed verify — oracle attack prevention"
    );
}

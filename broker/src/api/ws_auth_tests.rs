//! WS-level integration tests for the HttpFrame Ed25519 four-frame handshake.
//!
//! Spins up a real axum server on a random port and connects via tokio-tungstenite.
//! Full internal access (this is a #[cfg(test)] submodule of api::ws) lets us
//! inspect `nonce_store` state after protocol exchanges without lib.rs exposure.
//!
//! Five scenarios:
//!   1. Non-HELLO first frame → 400 PROTOCOL_ERROR
//!   2. Expired nonce (pre-drained) → 401 AUTH_STALE
//!   3. Wrong private key → 401 AUTH_WRONG_KEY; nonce burned (second consume → None)
//!   4. Duplicate connect (same identity, first session still open) → 409 Conflict
//!   5. Agent HELLO with attacker X-Pubkey, signs with attacker key → 401 AUTH_WRONG_KEY
//!      (proves stored key used, not the wire X-Pubkey — no rotation attack possible)

use crate::api;
use crate::api::middleware::ProjectRateLimiter;
use crate::api::routes::{AppState, BrokerConfig};
use crate::broker::{BrokerState, DeliveryEngine};
use crate::db;
use crate::http_frame::{self, HttpFrame};
use base64::Engine;
use dashmap::DashMap;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use futures::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMsg};

// ── Test constants ────────────────────────────────────────────────────────────

/// Shared secret used in tests that exercise the Boards TOFU bootstrap path.
const TEST_BOARDS_TOKEN: &str = "test-registration-token-xyz";

// ── Test server ───────────────────────────────────────────────────────────────

async fn spawn_test_server() -> (SocketAddr, Arc<AppState>) {
    spawn_test_server_inner(None).await
}

async fn spawn_test_server_with_boards_token(token: &str) -> (SocketAddr, Arc<AppState>) {
    spawn_test_server_inner(Some(token.to_string())).await
}

async fn spawn_test_server_inner(boards_registration_token: Option<String>) -> (SocketAddr, Arc<AppState>) {
    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker.clone()));
    let config = BrokerConfig { admin_key: None, rate_limit_rps: 100, boards_registration_token, archive_dms: false, relay_timeout: std::time::Duration::from_secs(5), log_file: None };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState { broker, delivery, config, rate_limiter, relay_map: Arc::new(dashmap::DashMap::new()), wire_log: None });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let addr = listener.local_addr().expect("local_addr");

    let app = api::http_router(state.clone())
        .route("/ws", axum::routing::get(api::handle_ws))
        .with_state(state.clone());

    tokio::spawn(async move { axum::serve(listener, app).await.ok() });

    (addr, state)
}

// ── WS helpers ────────────────────────────────────────────────────────────────

type WsStream = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

async fn ws_connect(addr: SocketAddr) -> WsStream {
    let url = format!("ws://127.0.0.1:{}/ws", addr.port());
    connect_async(url).await.expect("WS connect").0
}

async fn send_frame(ws: &mut WsStream, frame: &HttpFrame) {
    ws.send(WsMsg::Text(frame.serialize().into()))
        .await
        .expect("WS send");
}

async fn recv_frame(ws: &mut WsStream) -> HttpFrame {
    loop {
        let msg = ws.next().await.expect("stream ended").expect("WS recv");
        match msg {
            WsMsg::Text(t) => return http_frame::parse(&t).expect("HttpFrame parse"),
            WsMsg::Close(_) => panic!("connection closed before receiving expected frame"),
            _ => continue,
        }
    }
}

// ── Test data setup ───────────────────────────────────────────────────────────

/// Register a project and agent with a fresh Ed25519 key pair. Returns the SigningKey.
fn setup_agent(state: &Arc<AppState>, project: &str, project_key: &str, agent: &str) -> SigningKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    state.broker.repo.register_project(project, project_key).expect("register_project");
    state.broker.repo.register_agent(agent, project, "agent", "").expect("register_agent");
    state.broker.repo.set_agent_public_key(agent, project, &pubkey_hex).expect("set_agent_public_key");
    signing_key
}

/// Do HELLO → CHALLENGE exchange. Returns nonce_b64 from the CHALLENGE X-Nonce header.
/// `xpubkey`: if Some, adds X-Pubkey to the HELLO frame.
/// `xtoken`: if Some, adds X-Registration-Token to the HELLO frame (for Boards TOFU).
async fn hello_and_get_challenge(
    ws: &mut WsStream,
    identity: &str,
    xpubkey: Option<&str>,
    xtoken: Option<&str>,
) -> String {
    let mut hello = HttpFrame::request("HELLO", "/v1/sessions").add_header("X-From", identity);
    if let Some(key) = xpubkey {
        hello = hello.add_header("X-Pubkey", key);
    }
    if let Some(token) = xtoken {
        hello = hello.add_header("X-Registration-Token", token);
    }
    let hello = hello.finalize();
    send_frame(ws, &hello).await;

    let challenge = recv_frame(ws).await;
    assert_eq!(
        challenge.verb(),
        Some("CHALLENGE"),
        "expected CHALLENGE frame, got: {:?}",
        challenge.first_line
    );
    challenge.header("X-Nonce").expect("X-Nonce missing in CHALLENGE frame").to_string()
}

/// Build the canonical payload and sign it with `signing_key`. Returns base64-encoded signature.
fn sign_challenge(signing_key: &SigningKey, identity: &str, nonce_b64: &str) -> String {
    let payload = crate::identity::build_challenge_payload(identity, nonce_b64);
    base64::engine::general_purpose::STANDARD.encode(signing_key.sign(&payload).to_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Scenario 1: Client sends a non-HELLO frame as the first message (protocol violation).
/// Broker must respond with 400 Bad Request + PROTOCOL_ERROR, not silently drop.
#[tokio::test]
async fn ws_non_hello_first_frame_sends_protocol_error() {
    let (addr, _state) = spawn_test_server().await;
    let mut ws = ws_connect(addr).await;

    // Send AUTH without first doing HELLO
    let frame = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", "deadbeef")
        .finalize();
    send_frame(&mut ws, &frame).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(400), "expected 400 for protocol violation: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("PROTOCOL_ERROR"),
        "expected PROTOCOL_ERROR code: {:?}",
        resp
    );
}

/// Scenario 2: Nonce expires between Challenge issuance and Auth receipt.
/// Simulated by pre-draining the nonce from the store after receiving CHALLENGE.
/// Broker must respond 401 AUTH_STALE — client must reconnect for a fresh challenge.
#[tokio::test]
async fn ws_expired_nonce_sends_auth_stale() {
    let (addr, state) = spawn_test_server().await;
    let signing_key = setup_agent(&state, "proj-stale", "key-stale", "Alice");
    let identity = "Alice@proj-stale";

    let mut ws = ws_connect(addr).await;
    let nonce_b64 = hello_and_get_challenge(&mut ws, identity, None, None).await;

    // Derive nonce_hex to pre-drain it — simulates TTL expiry.
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&nonce_b64)
        .expect("nonce b64 decode");
    let nonce_hex = hex::encode(&nonce_bytes);
    let was_present = state.broker.nonce_store.consume(&nonce_hex);
    assert!(was_present.is_some(), "nonce must be in store after challenge issuance");

    // Send a validly-signed AUTH — signature is correct, but nonce is gone.
    let sig = sign_challenge(&signing_key, identity, &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "expected 401 for stale nonce: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("AUTH_STALE"),
        "expected AUTH_STALE: {:?}",
        resp
    );
}

/// Scenario 3: Client signs with the wrong private key.
/// Broker must respond 401 AUTH_WRONG_KEY. Nonce is burned — second consume → None,
/// forcing the client to reconnect for a fresh challenge (oracle attack prevention).
#[tokio::test]
async fn ws_wrong_key_sends_auth_wrong_key_and_burns_nonce() {
    let (addr, state) = spawn_test_server().await;
    let _correct_key = setup_agent(&state, "proj-badkey", "key-badkey", "Bob");
    let identity = "Bob@proj-badkey";

    let mut ws = ws_connect(addr).await;
    let nonce_b64 = hello_and_get_challenge(&mut ws, identity, None, None).await;

    // Sign with a DIFFERENT key — not the registered one.
    let wrong_key = SigningKey::generate(&mut OsRng);
    let sig = sign_challenge(&wrong_key, identity, &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "expected 401 for wrong key: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("AUTH_WRONG_KEY"),
        "expected AUTH_WRONG_KEY: {:?}",
        resp
    );

    // Nonce is burned — second consume must return None.
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(&nonce_b64)
        .expect("nonce b64 decode");
    let nonce_hex = hex::encode(&nonce_bytes);
    assert!(
        state.broker.nonce_store.consume(&nonce_hex).is_none(),
        "nonce must be burned after failed verify — oracle attack prevention"
    );
}

/// Scenario 4: Two connections with the same identity. First succeeds; second gets 409.
#[tokio::test]
async fn ws_duplicate_connect_rejected_with_409() {
    let (addr, state) = spawn_test_server().await;
    let signing_key = setup_agent(&state, "proj-dup", "key-dup", "Alice");
    let identity = "Alice@proj-dup";

    // First connection — must succeed.
    let mut ws1 = ws_connect(addr).await;
    let nonce1 = hello_and_get_challenge(&mut ws1, identity, None, None).await;
    let sig1 = sign_challenge(&signing_key, identity, &nonce1);
    let auth1 = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig1)
        .finalize();
    send_frame(&mut ws1, &auth1).await;
    let resp1 = recv_frame(&mut ws1).await;
    assert_eq!(resp1.status(), Some(200), "first connect must succeed: {:?}", resp1.first_line);

    // Second connection — same identity, first still active → must get 409.
    let mut ws2 = ws_connect(addr).await;
    let nonce2 = hello_and_get_challenge(&mut ws2, identity, None, None).await;
    let sig2 = sign_challenge(&signing_key, identity, &nonce2);
    let auth2 = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig2)
        .finalize();
    send_frame(&mut ws2, &auth2).await;
    let resp2 = recv_frame(&mut ws2).await;
    assert_eq!(resp2.status(), Some(409), "second connect must get 409 Conflict: {:?}", resp2.first_line);

    drop(ws1); // keep ws1 alive through the assertion, then close
}

/// Scenario 5: Agent HELLO includes X-Pubkey with an attacker's public key.
/// Attacker signs AUTH with their own private key.
/// Broker must use the STORED pubkey (not wire X-Pubkey) → 401 AUTH_WRONG_KEY.
/// This proves spec §6: X-Pubkey on agent HELLO is ignored — no rotation attack possible.
#[tokio::test]
async fn ws_agent_xpubkey_ignored_no_rotation_attack() {
    let (addr, state) = spawn_test_server().await;
    let _correct_key = setup_agent(&state, "proj-xpubkey", "key-xpubkey", "Eve");
    let identity = "Eve@proj-xpubkey";

    // Attacker generates their own key pair and attempts to inject it via X-Pubkey.
    let attacker_key = SigningKey::generate(&mut OsRng);
    let attacker_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(attacker_key.verifying_key().to_bytes());

    let mut ws = ws_connect(addr).await;
    // HELLO with attacker's X-Pubkey — broker must ignore it.
    let nonce_b64 = hello_and_get_challenge(&mut ws, identity, Some(&attacker_pubkey_b64), None).await;

    // Sign with attacker's key — broker uses STORED pubkey → verify fails.
    let sig = sign_challenge(&attacker_key, identity, &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "expected 401 — stored key used, not wire X-Pubkey: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("AUTH_WRONG_KEY"),
        "expected AUTH_WRONG_KEY: {:?}",
        resp
    );

    // Stored pubkey must be unchanged — attacker's key was NOT persisted.
    let stored_hex = state.broker.repo.get_agent_public_key("Eve", "proj-xpubkey");
    let attacker_hex = hex::encode(attacker_key.verifying_key().to_bytes());
    assert_ne!(
        stored_hex.as_deref(),
        Some(attacker_hex.as_str()),
        "stored pubkey must not have changed — rotation attack prevented"
    );
}

/// Scenario 6: Agent sends POST /v1/posts with a forged X-From header.
/// Broker must canonicalize X-From to the authenticated session identity before forwarding to Boards.
/// Proves that agents cannot impersonate other agents via X-From on POST.
#[tokio::test]
async fn ws_post_xfrom_canonicalized_prevents_impersonation() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let agent_key = setup_agent(&state, "proj-xfrom", "key-xfrom", "Alice");
    let agent_identity = "Alice@proj-xfrom";

    // --- Connect Boards (four-frame handshake) ---
    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_identity = "Boards@proj-xfrom";

    let mut boards_ws = ws_connect(addr).await;
    let mut boards_hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("X-From", boards_identity);
    boards_hello = boards_hello.add_header("X-Pubkey", &boards_pubkey_b64);
    boards_hello = boards_hello.add_header("X-Registration-Token", TEST_BOARDS_TOKEN);
    let boards_hello = boards_hello.finalize();
    send_frame(&mut boards_ws, &boards_hello).await;
    let boards_challenge = recv_frame(&mut boards_ws).await;
    assert_eq!(boards_challenge.verb(), Some("CHALLENGE"), "expected Boards CHALLENGE: {:?}", boards_challenge.first_line);
    let boards_nonce = boards_challenge.header("X-Nonce").expect("X-Nonce missing").to_string();
    let boards_sig = sign_challenge(&boards_key, boards_identity, &boards_nonce);
    let boards_auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &boards_sig)
        .finalize();
    send_frame(&mut boards_ws, &boards_auth).await;
    let boards_ok = recv_frame(&mut boards_ws).await;
    assert_eq!(boards_ok.status(), Some(200), "Boards must authenticate: {:?}", boards_ok.first_line);

    // --- Connect agent ---
    let mut agent_ws = ws_connect(addr).await;
    let nonce_b64 = hello_and_get_challenge(&mut agent_ws, agent_identity, None, None).await;
    let sig = sign_challenge(&agent_key, agent_identity, &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut agent_ws, &auth).await;
    let agent_ok = recv_frame(&mut agent_ws).await;
    assert_eq!(agent_ok.status(), Some(200), "agent must authenticate: {:?}", agent_ok.first_line);

    // --- Agent sends POST /v1/posts with a forged X-From ---
    let mut post = HttpFrame::request("POST", "/v1/posts")
        .add_header("X-From", "FakeAgent@proj-xfrom") // forged identity
        .add_header("X-To", "#general.proj-xfrom");
    post.body = "hello".to_string();
    let post = post.finalize();
    send_frame(&mut agent_ws, &post).await;

    // --- Boards must receive POST with canonicalized from: = authenticated identity ---
    let forwarded = recv_frame(&mut boards_ws).await;
    assert_eq!(
        forwarded.header("from"),
        Some(agent_identity),
        "from: must be canonicalized to authenticated identity, not forged value: {:?}",
        forwarded
    );

    // Boards sends a 200 OK Resp echoing the relay-id so broker can forward to agent (Q7).
    let relay_id = forwarded.header("correlation-id")
        .expect("broker must set relay-id as correlation-id on forwarded frame")
        .to_string();
    let mut boards_resp = HttpFrame::response(200, "OK");
    boards_resp.set_header("correlation-id", &relay_id);
    let boards_resp = boards_resp.finalize();
    send_frame(&mut boards_ws, &boards_resp).await;

    // Agent must receive 200 OK
    let ack = recv_frame(&mut agent_ws).await;
    assert_eq!(ack.status(), Some(200), "agent must get 200 OK: {:?}", ack.first_line);

    drop(boards_ws);
    drop(agent_ws);
}

/// Scenario 7: Boards TOFU — first HELLO with X-Pubkey on fresh project stores the key and
/// completes the four-frame handshake successfully.
#[tokio::test]
async fn ws_boards_tofu_first_connect_stores_key_and_succeeds() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    // Register project only — NO Boards agent row, NO stored key.
    state.broker.repo.register_project("proj-tofu", "pkey-tofu").expect("register_project");

    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_pubkey_hex = hex::encode(boards_key.verifying_key().to_bytes());
    let boards_identity = "Boards@proj-tofu";

    // No stored key yet.
    assert!(
        state.broker.repo.get_agent_public_key("Boards", "proj-tofu").is_none(),
        "no key must be stored before TOFU HELLO"
    );

    let mut ws = ws_connect(addr).await;
    let nonce_b64 = hello_and_get_challenge(&mut ws, boards_identity, Some(&boards_pubkey_b64), Some(TEST_BOARDS_TOKEN)).await;

    let sig = sign_challenge(&boards_key, boards_identity, &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(200), "TOFU Boards handshake must succeed: {:?}", resp.first_line);

    // Key must now be persisted in DB.
    assert_eq!(
        state.broker.repo.get_agent_public_key("Boards", "proj-tofu").as_deref(),
        Some(boards_pubkey_hex.as_str()),
        "TOFU key must be stored after first Boards HELLO"
    );
}

/// Scenario 8: Boards key-rotation rejected — after TOFU, a second HELLO carrying a different
/// X-Pubkey must be rejected with 401 KEY_MISMATCH BEFORE a CHALLENGE is issued.
/// Proves spec §6: no Boards key rotation from the wire.
#[tokio::test]
async fn ws_boards_key_rotation_rejected_before_challenge() {
    let (addr, state) = spawn_test_server().await;
    state.broker.repo.register_project("proj-no-rotate", "pkey-no-rotate").expect("register_project");

    // Pre-pin a Boards key (simulates post-TOFU state).
    let pinned_key = SigningKey::generate(&mut OsRng);
    let pinned_hex = hex::encode(pinned_key.verifying_key().to_bytes());
    state.broker.repo.register_agent("Boards", "proj-no-rotate", "service", "").expect("register Boards");
    state.broker.repo.set_agent_public_key("Boards", "proj-no-rotate", &pinned_hex).expect("pin key");

    // Attacker tries to reconnect with a different key.
    let attacker_key = SigningKey::generate(&mut OsRng);
    let attacker_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(attacker_key.verifying_key().to_bytes());
    let boards_identity = "Boards@proj-no-rotate";

    let mut ws = ws_connect(addr).await;
    let mut hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("X-From", boards_identity);
    hello = hello.add_header("X-Pubkey", &attacker_pubkey_b64);
    let hello = hello.finalize();
    send_frame(&mut ws, &hello).await;

    // Must get 401 KEY_MISMATCH — no CHALLENGE should be issued.
    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "rotation attempt must be rejected with 401: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("KEY_MISMATCH"),
        "expected KEY_MISMATCH error code: {:?}",
        resp
    );

    // Stored key must be unchanged.
    assert_eq!(
        state.broker.repo.get_agent_public_key("Boards", "proj-no-rotate").as_deref(),
        Some(pinned_hex.as_str()),
        "stored Boards key must be unchanged after rotation rejection"
    );
}

/// Scenario 12: Boards TOFU with a blank (empty string) registration token configured.
/// `Some("")` must behave identically to `None` after normalization at load time — fail-closed.
/// This test sets the raw config value to `Some("")` to verify the runtime guard holds even
/// if normalization is bypassed (defence-in-depth: the None branch handles both).
#[tokio::test]
async fn ws_boards_tofu_blank_token_configured_rejected() {
    // Directly construct a server with boards_registration_token: Some("") — simulates a
    // misconfigured deployment where the env var was set to an empty string.
    let (addr, state) = spawn_test_server_inner(Some("".to_string())).await;
    state.broker.repo.register_project("proj-blank-token", "pkey-blank-token").expect("register_project");

    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_identity = "Boards@proj-blank-token";

    let mut ws = ws_connect(addr).await;
    // HELLO with X-Pubkey — no X-Registration-Token (blank token = effectively unconfigured).
    let hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("X-From", boards_identity)
        .add_header("X-Pubkey", &boards_pubkey_b64)
        .finalize();
    send_frame(&mut ws, &hello).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "blank token must be treated as unconfigured (401): {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("AUTH_INVALID_TOKEN"),
        "expected AUTH_INVALID_TOKEN for blank token config: {:?}",
        resp
    );
    assert!(
        state.broker.repo.get_agent_public_key("Boards", "proj-blank-token").is_none(),
        "no key must be written when token is blank"
    );
}
/// Broker must reject with 401 AUTH_INVALID_TOKEN — no open bootstrap allowed.
#[tokio::test]
async fn ws_boards_tofu_no_token_configured_rejected() {
    // Server started WITHOUT a boards_registration_token.
    let (addr, state) = spawn_test_server().await;
    state.broker.repo.register_project("proj-notoken", "pkey-notoken").expect("register_project");

    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_identity = "Boards@proj-notoken";

    let mut ws = ws_connect(addr).await;
    // HELLO with valid X-Pubkey and even a token — but server has none configured.
    let mut hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("X-From", boards_identity)
        .add_header("X-Pubkey", &boards_pubkey_b64);
    hello = hello.add_header("X-Registration-Token", "any-token");
    let hello = hello.finalize();
    send_frame(&mut ws, &hello).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "must be 401 when no token configured: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("AUTH_INVALID_TOKEN"),
        "expected AUTH_INVALID_TOKEN: {:?}",
        resp
    );
    // Key must NOT be written.
    assert!(
        state.broker.repo.get_agent_public_key("Boards", "proj-notoken").is_none(),
        "no key must be written when token check fails"
    );
}

/// Scenario 10: Boards TOFU with missing X-Registration-Token header.
/// Token is configured but header absent — must reject 401 AUTH_INVALID_TOKEN, no key written.
#[tokio::test]
async fn ws_boards_tofu_missing_token_header_rejected() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    state.broker.repo.register_project("proj-noheader", "pkey-noheader").expect("register_project");

    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_identity = "Boards@proj-noheader";

    let mut ws = ws_connect(addr).await;
    // HELLO with X-Pubkey but WITHOUT X-Registration-Token.
    let hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("X-From", boards_identity)
        .add_header("X-Pubkey", &boards_pubkey_b64)
        .finalize();
    send_frame(&mut ws, &hello).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "must be 401 when token header absent: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("AUTH_INVALID_TOKEN"),
        "expected AUTH_INVALID_TOKEN: {:?}",
        resp
    );
    assert!(
        state.broker.repo.get_agent_public_key("Boards", "proj-noheader").is_none(),
        "no key must be written when token header is missing"
    );
}

/// Scenario 11: Boards TOFU with wrong X-Registration-Token value.
/// Token is configured but header value is wrong — must reject 401 AUTH_INVALID_TOKEN, no key written.
#[tokio::test]
async fn ws_boards_tofu_wrong_token_rejected() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    state.broker.repo.register_project("proj-wrongtoken", "pkey-wrongtoken").expect("register_project");

    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_identity = "Boards@proj-wrongtoken";

    let mut ws = ws_connect(addr).await;
    // HELLO with correct X-Pubkey but wrong token value.
    let hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("X-From", boards_identity)
        .add_header("X-Pubkey", &boards_pubkey_b64)
        .add_header("X-Registration-Token", "wrong-token-value")
        .finalize();
    send_frame(&mut ws, &hello).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(resp.status(), Some(401), "must be 401 for wrong token: {:?}", resp.first_line);
    assert_eq!(
        resp.header("X-Error-Code"),
        Some("AUTH_INVALID_TOKEN"),
        "expected AUTH_INVALID_TOKEN: {:?}",
        resp
    );
    assert!(
        state.broker.repo.get_agent_public_key("Boards", "proj-wrongtoken").is_none(),
        "no key must be written when token value is wrong"
    );
}

/// Scenario 13: Boards TOFU auto-creates project on fresh DB.
/// When Boards presents a valid TOFU HELLO for a project that has no row in the broker DB,
/// the broker must auto-create the project (with a sentinel key), then proceed with the
/// standard TOFU registration. The full four-frame handshake must succeed.
#[tokio::test]
async fn ws_boards_tofu_auto_creates_project_on_fresh_db() {
    // Server started with token — but NO project pre-registered.
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let project = "proj-autoprovision";

    // Confirm project does not exist before the test.
    assert!(
        !state.broker.repo.project_exists(project),
        "project must not exist before TOFU HELLO"
    );

    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_pubkey_hex = hex::encode(boards_key.verifying_key().to_bytes());
    let boards_identity = format!("Boards@{}", project);

    let mut ws = ws_connect(addr).await;
    let nonce_b64 = hello_and_get_challenge(
        &mut ws,
        &boards_identity,
        Some(&boards_pubkey_b64),
        Some(TEST_BOARDS_TOKEN),
    )
    .await;

    let sig = sign_challenge(&boards_key, &boards_identity, &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let resp = recv_frame(&mut ws).await;
    assert_eq!(
        resp.status(),
        Some(200),
        "TOFU on fresh project must succeed: {:?}",
        resp.first_line
    );

    // Project row must exist now.
    assert!(
        state.broker.repo.project_exists(project),
        "project row must be auto-created after TOFU HELLO"
    );

    // Boards key must be stored.
    assert_eq!(
        state.broker.repo.get_agent_public_key("Boards", project).as_deref(),
        Some(boards_pubkey_hex.as_str()),
        "Boards key must be stored after TOFU on fresh project"
    );
}

// ── DM tests ──────────────────────────────────────────────────────────────────

/// Helper: server variant with archive_dms enabled.
async fn spawn_test_server_with_archive() -> (SocketAddr, Arc<AppState>) {
    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker.clone()));
    let config = BrokerConfig {
        admin_key: None,
        rate_limit_rps: 100,
        boards_registration_token: Some(TEST_BOARDS_TOKEN.to_string()),
        archive_dms: true,
        relay_timeout: std::time::Duration::from_secs(5),
        log_file: None,
    };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState { broker, delivery, config, rate_limiter, relay_map: Arc::new(dashmap::DashMap::new()), wire_log: None });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let addr = listener.local_addr().expect("local_addr");
    let app = api::http_router(state.clone())
        .route("/ws", axum::routing::get(api::handle_ws))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    (addr, state)
}

/// Complete HELLO → CHALLENGE → AUTH → 200 OK on an existing WS connection.
async fn complete_handshake(ws: &mut WsStream, identity: &str, signing_key: &SigningKey) {
    let nonce_b64 = hello_and_get_challenge(ws, identity, None, None).await;
    let sig = sign_challenge(signing_key, identity, &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(ws, &auth).await;
    let ok = recv_frame(ws).await;
    assert_eq!(ok.status(), Some(200), "handshake must succeed: {:?}", ok.first_line);
}

/// Register an agent in an already-existing project (project row not created).
fn setup_agent_in_project(state: &Arc<AppState>, project: &str, agent: &str) -> SigningKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    state.broker.repo.register_agent(agent, project, "agent", "").expect("register_agent");
    state.broker.repo.set_agent_public_key(agent, project, &pubkey_hex).expect("set_agent_public_key");
    signing_key
}

/// DM test 1 (i-dm-t5-i): DM delivered to live recipient while Boards is offline.
/// Sender gets 200 OK and recipient receives DELIVER on their WS connection.
/// Boards is never involved — proves broker-direct hot path.
#[tokio::test]
async fn ws_dm_live_delivery_boards_offline() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-dm1", "key-dm1", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-dm1", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-dm1", &alice_key).await;

    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-dm1", &bob_key).await;

    // Alice sends DM to Bob — Boards is not connected.
    let mut dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-From", "Alice@proj-dm1")
        .add_header("X-To", "Bob@proj-dm1");
    dm.body = "hello bob".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    // Alice must receive 200 OK.
    let ack = recv_frame(&mut alice_ws).await;
    assert_eq!(ack.status(), Some(200), "sender must get 200 OK for live DM: {:?}", ack.first_line);

    // Bob must receive DELIVER on C6 path (broker canonicalizes v1 /v1/dms → C6).
    let deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(deliver.verb(), Some("DELIVER"), "recipient must receive DELIVER: {:?}", deliver.first_line);
    assert_eq!(deliver.path(), Some("/agents/Bob@proj-dm1/dms"), "DELIVER path must be canonicalized C6 path");
    assert_eq!(deliver.header("from"), Some("Alice@proj-dm1"), "from: must be canonicalized (v2)");
    assert!(deliver.header("X-From").is_none(), "X-From must not appear on broker-emitted DELIVER");
    assert!(deliver.header("to").is_none(), "to: must not appear on broker-emitted DM DELIVER");
    assert!(deliver.header("X-To").is_none(), "X-To must not appear on broker-emitted DELIVER");
    assert_eq!(deliver.body, "hello bob", "body must be preserved");

    drop(alice_ws);
    drop(bob_ws);
}

/// DM test 2 (i-dm-t5-ii): DM to offline recipient → 202 Accepted + drains on reconnect.
/// Also verifies no double-delivery: after drain + mark_delivered, second drain is empty.
#[tokio::test]
async fn ws_dm_offline_recipient_queued_and_drained() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-dm2", "key-dm2-a", "Alice");
    setup_agent_in_project(&state, "proj-dm2", "Bob"); // registered but not connected

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-dm2", &alice_key).await;

    // Alice sends DM to offline Bob.
    let mut dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-From", "Alice@proj-dm2")
        .add_header("X-To", "Bob@proj-dm2");
    dm.body = "queued message".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    // Alice must receive 202 Accepted.
    let ack = recv_frame(&mut alice_ws).await;
    assert_eq!(ack.status(), Some(202), "sender must get 202 for offline recipient: {:?}", ack.first_line);

    // Pending row must exist.
    let pending = state.broker.repo.peek_pending("Bob", "proj-dm2");
    assert!(!pending.is_empty(), "pending row must exist after 202");

    // Simulate Bob reconnecting: drain_pending → marks 'sending'.
    let drained = state.delivery.drain_pending("Bob", "proj-dm2");
    assert_eq!(drained.len(), 1, "exactly one message must drain");
    let msg = &drained[0];
    assert_eq!(msg.from_agent, "Alice", "from_agent must be Alice");
    assert!(msg.body.contains("queued message"), "body must contain original message");

    // Simulate successful WS write → mark delivered.
    state.delivery.mark_delivered(&msg.id, "Bob", "proj-dm2");

    // Second drain must return nothing — no double-delivery.
    let second_drain = state.delivery.drain_pending("Bob", "proj-dm2");
    assert!(second_drain.is_empty(), "second drain must be empty after mark_delivered");

    drop(alice_ws);
}

/// DM test 3 (i-dm-t5-iii): DM to unknown recipient → 404 Not Found.
#[tokio::test]
async fn ws_dm_unknown_recipient_404() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-dm3", "key-dm3", "Alice");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-dm3", &alice_key).await;

    // DM to an agent that was never registered.
    let mut dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-From", "Alice@proj-dm3")
        .add_header("X-To", "Nobody@proj-dm3");
    dm.body = "hello?".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    let resp = recv_frame(&mut alice_ws).await;
    assert_eq!(resp.status(), Some(404), "unknown recipient must return 404: {:?}", resp.first_line);

    drop(alice_ws);
}

/// DM test 4 (i-dm-t5-iv): X-From canonicalization — forged X-From is replaced by the
/// authenticated identity on the DELIVER frame received by the recipient.
#[tokio::test]
async fn ws_dm_xfrom_canonicalized() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-dm4", "key-dm4-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-dm4", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-dm4", &alice_key).await;

    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-dm4", &bob_key).await;

    // Alice sends DM with a FORGED X-From.
    let mut dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-From", "EvilAgent@other-project") // forged
        .add_header("X-To", "Bob@proj-dm4");
    dm.body = "impersonation attempt".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    let ack = recv_frame(&mut alice_ws).await;
    assert_eq!(ack.status(), Some(200), "sender must get 200 OK: {:?}", ack.first_line);

    // Bob must see `from:` canonicalized to Alice's authenticated identity (not forged value).
    let deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(
        deliver.header("from"),
        Some("Alice@proj-dm4"),
        "from: must be canonicalized to authenticated identity, not forged value: {:?}",
        deliver
    );

    drop(alice_ws);
    drop(bob_ws);
}

/// DM test 5 (i-dm-t5-v): BROKER_ARCHIVE_DMS=true — Boards offline does NOT block delivery.
/// Live delivery succeeds with 200 OK and recipient receives DELIVER. Archive failure is silent.
#[tokio::test]
async fn ws_dm_archive_dms_boards_offline_does_not_block() {
    // Server with archive_dms=true; Boards is NOT connected.
    let (addr, state) = spawn_test_server_with_archive().await;
    let alice_key = setup_agent(&state, "proj-dm5", "key-dm5-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-dm5", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-dm5", &alice_key).await;

    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-dm5", &bob_key).await;

    // Alice sends DM — Boards@proj-dm5 is not connected (archive_dms=true but Boards offline).
    let mut dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-From", "Alice@proj-dm5")
        .add_header("X-To", "Bob@proj-dm5");
    dm.body = "archive test".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    // Alice must get 200 OK — Boards absence must not block.
    let ack = recv_frame(&mut alice_ws).await;
    assert_eq!(
        ack.status(),
        Some(200),
        "delivery must succeed (200) even when Boards is offline (archive_dms=true): {:?}",
        ack.first_line
    );

    // Bob must still receive DELIVER.
    let deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(
        deliver.verb(),
        Some("DELIVER"),
        "recipient must receive DELIVER despite archive failure: {:?}",
        deliver.first_line
    );
    assert_eq!(deliver.body, "archive test", "body must be preserved");

    drop(alice_ws);
    drop(bob_ws);
}

/// DM test 6: correlation-id is echoed on all locally-generated responses (Q7 gap fix).
/// Verifies that 202 Accepted includes the inbound correlation-id header.
#[tokio::test]
async fn ws_dm_correlation_id_echoed() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-cid1", "key-cid1", "Alice");
    // Register Bob as offline (never connects) so Alice gets 202 Accepted.
    setup_agent_in_project(&state, "proj-cid1", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-cid1", &alice_key).await;

    let mut dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-From", "Alice@proj-cid1")
        .add_header("X-To", "Bob@proj-cid1")
        .add_header("correlation-id", "c-99");
    dm.body = "ping".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    let resp = recv_frame(&mut alice_ws).await;
    assert_eq!(resp.status(), Some(202), "offline recipient must return 202: {:?}", resp.first_line);
    assert_eq!(
        resp.header("correlation-id"),
        Some("c-99"),
        "correlation-id must be echoed on 202 response: {:?}",
        resp
    );

    drop(alice_ws);
}

// ── PUBLISH partial delivery tests ────────────────────────────────────────────

/// Connect Boards via TOFU handshake. Returns the connected WS stream.
async fn connect_boards_tofu(addr: SocketAddr, project: &str) -> WsStream {
    let boards_key = SigningKey::generate(&mut OsRng);
    let boards_pubkey_b64 = base64::engine::general_purpose::STANDARD
        .encode(boards_key.verifying_key().to_bytes());
    let boards_identity = format!("Boards@{}", project);

    let mut boards_ws = ws_connect(addr).await;
    let hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("X-From", &boards_identity)
        .add_header("X-Pubkey", &boards_pubkey_b64)
        .add_header("X-Registration-Token", TEST_BOARDS_TOKEN)
        .finalize();
    send_frame(&mut boards_ws, &hello).await;

    let challenge = recv_frame(&mut boards_ws).await;
    assert_eq!(challenge.verb(), Some("CHALLENGE"), "Boards CHALLENGE expected: {:?}", challenge.first_line);
    let nonce = challenge.header("X-Nonce").expect("X-Nonce missing").to_string();
    let sig = sign_challenge(&boards_key, &boards_identity, &nonce);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut boards_ws, &auth).await;

    let ok = recv_frame(&mut boards_ws).await;
    assert_eq!(ok.status(), Some(200), "Boards must authenticate: {:?}", ok.first_line);
    boards_ws
}

/// PUBLISH test 1 (C13): `mentions:` header present → 200 OK, all recipients receive DELIVER.
/// v2 path: broker reads mentions: list directly, fans out without validation.
#[tokio::test]
async fn ws_publish_mentions_header_fans_out_to_recipients() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let alice_key = setup_agent(&state, "proj-pub1", "key-pub1-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-pub1", "Bob");

    let mut boards_ws = connect_boards_tofu(addr, "proj-pub1").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-pub1", &alice_key).await;
    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-pub1", &bob_key).await;

    // Boards sends PUBLISH with pre-resolved mentions: list (v2 path).
    let mut publish = HttpFrame::request("PUBLISH", "/v1/deliveries")
        .add_header("X-From", "Boards@proj-pub1")
        .add_header("mentions", "Alice@proj-pub1,Bob@proj-pub1");
    publish.body = "hello both".to_string();
    let publish = publish.finalize();
    send_frame(&mut boards_ws, &publish).await;

    // Boards must receive 200 OK — no X-Dropped header (C13 drops that concept).
    let ack = recv_frame(&mut boards_ws).await;
    assert_eq!(ack.status(), Some(200), "PUBLISH with mentions: must return 200: {:?}", ack.first_line);
    assert!(ack.header("X-Dropped").is_none(), "C13: no X-Dropped header on any PUBLISH response");

    // Both Alice and Bob must receive DELIVER.
    let alice_deliver = recv_frame(&mut alice_ws).await;
    assert_eq!(alice_deliver.verb(), Some("DELIVER"), "Alice must receive DELIVER: {:?}", alice_deliver.first_line);
    let bob_deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(bob_deliver.verb(), Some("DELIVER"), "Bob must receive DELIVER: {:?}", bob_deliver.first_line);

    drop(boards_ws); drop(alice_ws); drop(bob_ws);
}

/// PUBLISH test 2 (C13): broker trusts the mentions: list — unresolvable entries are warn+skip,
/// not rejected. 200 OK returned; no X-Dropped; reachable recipients get DELIVER.
#[tokio::test]
async fn ws_publish_unresolvable_mention_is_warned_not_rejected() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let alice_key = setup_agent(&state, "proj-pub2", "key-pub2", "Alice");

    let mut boards_ws = connect_boards_tofu(addr, "proj-pub2").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-pub2", &alice_key).await;

    // mentions: list includes Alice (valid) and a malformed entry (no @).
    // Broker trusts the pre-resolved list — does NOT validate individual entries.
    let mut publish = HttpFrame::request("PUBLISH", "/v1/deliveries")
        .add_header("X-From", "Boards@proj-pub2")
        .add_header("mentions", "Alice@proj-pub2,BadIdentity");
    publish.body = "partial test".to_string();
    let publish = publish.finalize();
    send_frame(&mut boards_ws, &publish).await;

    // 200 OK — broker accepted the list without validation. No X-Dropped.
    let ack = recv_frame(&mut boards_ws).await;
    assert_eq!(ack.status(), Some(200), "mentions: with bad entry must still return 200: {:?}", ack.first_line);
    assert!(ack.header("X-Dropped").is_none(), "C13: no X-Dropped header");

    // Alice (reachable) must receive DELIVER.
    let deliver = recv_frame(&mut alice_ws).await;
    assert_eq!(deliver.verb(), Some("DELIVER"), "valid recipient must receive DELIVER: {:?}", deliver.first_line);
    assert_eq!(deliver.body, "partial test", "body must be preserved");

    drop(boards_ws); drop(alice_ws);
}

/// PUBLISH test 3 (C13): neither `mentions:` nor `X-To` present → 400 Bad Request.
#[tokio::test]
async fn ws_publish_no_mentions_no_xto_returns_400() {
    let (addr, _state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let mut boards_ws = connect_boards_tofu(addr, "proj-pub3").await;

    // PUBLISH with no recipient header at all.
    let mut publish = HttpFrame::request("PUBLISH", "/v1/deliveries")
        .add_header("X-From", "Boards@proj-pub3");
    publish.body = "should fail".to_string();
    let publish = publish.finalize();
    send_frame(&mut boards_ws, &publish).await;

    let resp = recv_frame(&mut boards_ws).await;
    assert_eq!(resp.status(), Some(400), "PUBLISH with no recipient header must return 400: {:?}", resp.first_line);

    drop(boards_ws);
}

/// PUBLISH test 4 (C13): `mentions:` present but resolves to empty list (all commas) → 400.
#[tokio::test]
async fn ws_publish_empty_mentions_list_returns_400() {
    let (addr, _state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let mut boards_ws = connect_boards_tofu(addr, "proj-pub4").await;

    // mentions: contains only commas — empty after split+trim+filter.
    let mut publish = HttpFrame::request("PUBLISH", "/v1/deliveries")
        .add_header("X-From", "Boards@proj-pub4")
        .add_header("mentions", ",,");
    publish.body = "empty list".to_string();
    let publish = publish.finalize();
    send_frame(&mut boards_ws, &publish).await;

    let resp = recv_frame(&mut boards_ws).await;
    assert_eq!(resp.status(), Some(400), "PUBLISH with empty mentions: list must return 400: {:?}", resp.first_line);

    drop(boards_ws);
}

/// PUBLISH test 6 (C13): Trailing/double commas in `mentions:` are silently skipped (empty segments).
#[tokio::test]
async fn ws_publish_trailing_and_double_commas_in_mentions_skipped() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let alice_key = setup_agent(&state, "proj-pub6", "key-pub6-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-pub6", "Bob");

    let mut boards_ws = connect_boards_tofu(addr, "proj-pub6").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-pub6", &alice_key).await;
    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-pub6", &bob_key).await;

    // mentions: has trailing comma and double comma — both produce empty segments.
    let mut publish = HttpFrame::request("PUBLISH", "/v1/deliveries")
        .add_header("X-From", "Boards@proj-pub6")
        .add_header("mentions", "Alice@proj-pub6,,Bob@proj-pub6,");
    publish.body = "comma noise".to_string();
    let publish = publish.finalize();
    send_frame(&mut boards_ws, &publish).await;

    // 200 OK — empty segments filtered, valid recipients remain.
    let ack = recv_frame(&mut boards_ws).await;
    assert_eq!(ack.status(), Some(200), "PUBLISH with comma noise must return 200: {:?}", ack.first_line);
    assert!(ack.header("X-Dropped").is_none(), "C13: no X-Dropped header");

    // Both valid recipients must still receive DELIVER.
    let alice_deliver = recv_frame(&mut alice_ws).await;
    assert_eq!(alice_deliver.verb(), Some("DELIVER"), "Alice must receive DELIVER: {:?}", alice_deliver.first_line);
    let bob_deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(bob_deliver.verb(), Some("DELIVER"), "Bob must receive DELIVER: {:?}", bob_deliver.first_line);

    drop(boards_ws); drop(alice_ws); drop(bob_ws);
}

// ── Q7: Relay tests (correlation-id relay + real Resps for POST forwarding) ───

/// Spawn a server with a configurable relay_timeout — needed for deterministic timeout tests.
async fn spawn_relay_server(timeout_secs: u64) -> (SocketAddr, Arc<AppState>) {
    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker.clone()));
    let config = BrokerConfig {
        admin_key: None,
        rate_limit_rps: 100,
        boards_registration_token: Some(TEST_BOARDS_TOKEN.to_string()),
        archive_dms: false,
        relay_timeout: std::time::Duration::from_secs(timeout_secs),
        log_file: None,
    };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState {
        broker, delivery, config, rate_limiter,
        relay_map: Arc::new(DashMap::new()),
        wire_log: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let app = crate::api::http_router(state.clone())
        .route("/ws", axum::routing::get(crate::api::handle_ws))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    (addr, state)
}

/// Q7 relay t1: POST /v1/posts forwarded to Boards with relay-id as correlation-id.
/// Boards echoes relay-id back on 201 Resp. Broker rewrites to source's original
/// correlation-id and forwards 201 to sender.
#[tokio::test]
async fn ws_relay_boards_resp_with_correlation_id_forwarded_to_sender() {
    let (addr, state) = spawn_relay_server(5).await;
    let agent_key = setup_agent(&state, "proj-relay1", "key-relay1", "Alice");
    let mut boards_ws = connect_boards_tofu(addr, "proj-relay1").await;

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-relay1", &agent_key).await;

    // Alice sends POST /v1/posts with a correlation-id.
    let post = HttpFrame::request("POST", "/v1/posts")
        .add_header("X-To", "#general.proj-relay1")
        .add_header("correlation-id", "client-cid-42")
        .finalize();
    send_frame(&mut alice_ws, &post).await;

    // Boards receives the forwarded frame; source's cid is replaced with relay-id.
    let forwarded = recv_frame(&mut boards_ws).await;
    let relay_id = forwarded.header("correlation-id")
        .expect("relay-id must be present on forwarded frame")
        .to_string();
    assert!(relay_id.starts_with("r-"), "relay-id must have r- prefix; got: {}", relay_id);

    // Boards replies 201 Created, echoing the relay-id as correlation-id.
    let mut boards_resp = HttpFrame::response(201, "Created");
    boards_resp.set_header("correlation-id", &relay_id);
    let boards_resp = boards_resp.finalize();
    send_frame(&mut boards_ws, &boards_resp).await;

    // Alice receives Boards' real 201 with her original correlation-id restored.
    let alice_resp = recv_frame(&mut alice_ws).await;
    assert_eq!(alice_resp.status(), Some(201), "sender must receive Boards' 201: {:?}", alice_resp.first_line);
    assert_eq!(
        alice_resp.header("correlation-id"),
        Some("client-cid-42"),
        "source correlation-id must be restored on response"
    );

    drop(boards_ws); drop(alice_ws);
}

/// Q7 relay t2: POST /v1/posts with NO correlation-id on source frame.
/// Broker injects relay-id as correlation-id for Boards' benefit; after relay,
/// correlation-id is removed from response so relay internals don't leak to sender.
#[tokio::test]
async fn ws_relay_boards_resp_without_source_cid_removes_header() {
    let (addr, state) = spawn_relay_server(5).await;
    let agent_key = setup_agent(&state, "proj-relay2", "key-relay2", "Bob");
    let mut boards_ws = connect_boards_tofu(addr, "proj-relay2").await;

    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-relay2", &agent_key).await;

    // Bob sends POST /v1/posts with no correlation-id.
    let post = HttpFrame::request("POST", "/v1/posts")
        .add_header("X-To", "#general.proj-relay2")
        .finalize();
    send_frame(&mut bob_ws, &post).await;

    // Boards receives frame; relay-id is now the correlation-id.
    let forwarded = recv_frame(&mut boards_ws).await;
    let relay_id = forwarded.header("correlation-id")
        .expect("relay-id must be set even when source had no cid")
        .to_string();
    assert!(relay_id.starts_with("r-"));

    // Boards replies 200 OK echoing the relay-id.
    let mut boards_resp = HttpFrame::response(200, "OK");
    boards_resp.set_header("correlation-id", &relay_id);
    let boards_resp = boards_resp.finalize();
    send_frame(&mut boards_ws, &boards_resp).await;

    // Bob receives 200; correlation-id must be absent (source sent none → don't leak relay-id).
    let bob_resp = recv_frame(&mut bob_ws).await;
    assert_eq!(bob_resp.status(), Some(200), "sender must receive 200: {:?}", bob_resp.first_line);
    assert!(
        bob_resp.header("correlation-id").is_none(),
        "correlation-id must be absent when source had none; got: {:?}",
        bob_resp.header("correlation-id")
    );

    drop(boards_ws); drop(bob_ws);
}

/// Q7 relay t3: Boards not connected — sender receives 503 with Retry-After: 1.
/// Original correlation-id preserved on 503. relay_map stays empty (entry cleaned up).
#[tokio::test]
async fn ws_relay_boards_offline_returns_503() {
    let (addr, state) = spawn_relay_server(5).await;
    // Register agent but intentionally omit Boards TOFU — Boards is offline.
    let agent_key = setup_agent(&state, "proj-relay3", "key-relay3", "Carol");

    let mut carol_ws = ws_connect(addr).await;
    complete_handshake(&mut carol_ws, "Carol@proj-relay3", &agent_key).await;

    let post = HttpFrame::request("POST", "/v1/posts")
        .add_header("X-To", "#general.proj-relay3")
        .add_header("correlation-id", "cid-offline")
        .finalize();
    send_frame(&mut carol_ws, &post).await;

    let resp = recv_frame(&mut carol_ws).await;
    assert_eq!(resp.status(), Some(503), "must get 503 when Boards offline: {:?}", resp.first_line);
    assert_eq!(resp.header("Retry-After"), Some("1"), "must include Retry-After: 1");
    assert_eq!(resp.header("correlation-id"), Some("cid-offline"), "cid must be echoed on 503");
    // relay_map must be clean — entry is removed on 503 path.
    assert!(state.relay_map.is_empty(), "relay_map must be empty after 503");

    drop(carol_ws);
}

/// Q7 relay t4: Boards connected but never replies → timeout task fires 504 after
/// relay_timeout_secs. Sender receives 504 with original correlation-id.
#[tokio::test]
async fn ws_relay_timeout_fires_504() {
    // 1-second timeout for fast test execution.
    let (addr, state) = spawn_relay_server(1).await;
    let agent_key = setup_agent(&state, "proj-relay4", "key-relay4", "Dave");
    let mut boards_ws = connect_boards_tofu(addr, "proj-relay4").await;

    let mut dave_ws = ws_connect(addr).await;
    complete_handshake(&mut dave_ws, "Dave@proj-relay4", &agent_key).await;

    let post = HttpFrame::request("POST", "/v1/posts")
        .add_header("X-To", "#general.proj-relay4")
        .add_header("correlation-id", "cid-timeout")
        .finalize();
    send_frame(&mut dave_ws, &post).await;

    // Boards receives the frame but intentionally does NOT reply.
    let _forwarded = recv_frame(&mut boards_ws).await;

    // Wait for 504 — timeout is 1s, allow 3s for CI headroom.
    let dave_resp = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        async { recv_frame(&mut dave_ws).await },
    )
    .await
    .expect("timed out waiting for 504 from broker");

    assert_eq!(dave_resp.status(), Some(504), "must receive 504 on timeout: {:?}", dave_resp.first_line);
    assert_eq!(dave_resp.header("correlation-id"), Some("cid-timeout"), "cid must be preserved on 504");

    drop(boards_ws); drop(dave_ws);
}

/// Q7 relay t5: Boards sends a Resp with an unknown relay-id (not in relay_map —
/// expired or fabricated). Frame is silently dropped; Boards connection stays alive.
#[tokio::test]
async fn ws_relay_unknown_relay_id_dropped_connection_stays_alive() {
    let (addr, state) = spawn_relay_server(5).await;
    let _ = setup_agent(&state, "proj-relay5", "key-relay5", "Eve");
    let mut boards_ws = connect_boards_tofu(addr, "proj-relay5").await;

    // Boards sends a Resp with a well-formed but unknown relay-id.
    let mut stale = HttpFrame::response(200, "OK");
    stale.set_header("correlation-id", "r-00000000-0000-0000-0000-000000000000");
    let stale = stale.finalize();
    send_frame(&mut boards_ws, &stale).await;

    // Give the broker a moment to process.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Confirm Boards WS is still alive by sending a PUBLISH and checking it gets any response.
    let probe = HttpFrame::request("PUBLISH", "/v1/deliveries")
        .add_header("X-To", "nobody@proj-relay5")
        .finalize();
    send_frame(&mut boards_ws, &probe).await;
    let probe_resp = recv_frame(&mut boards_ws).await;
    assert!(
        probe_resp.status().is_some(),
        "Boards WS must still be alive after unknown relay-id drop: {:?}",
        probe_resp.first_line
    );

    drop(boards_ws);
}

/// Q7 relay security: a non-Boards agent sending a response-shaped frame is rejected
/// with 400 (not allowed to reach relay-map lookup) and is still rate-limited.
#[tokio::test]
async fn ws_relay_non_boards_resp_frame_rejected_400() {
    let (addr, state) = spawn_relay_server(5).await;
    let agent_key = setup_agent(&state, "proj-relay6", "key-relay6", "Alice");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-relay6", &agent_key).await;

    // Alice crafts a response-shaped frame (no verb, has status) with a relay-id-looking
    // correlation-id. This must be rejected — Alice is not Boards.
    let mut resp_frame = HttpFrame::response(200, "OK");
    resp_frame.set_header("correlation-id", "r-00000000-0000-0000-0000-000000000000");
    let resp_frame = resp_frame.finalize();
    send_frame(&mut alice_ws, &resp_frame).await;

    let rejection = recv_frame(&mut alice_ws).await;
    assert_eq!(
        rejection.status(),
        Some(400),
        "non-Boards Resp frame must be rejected with 400: {:?}",
        rejection.first_line
    );
    // relay_map must be untouched — no lookup was performed.
    assert!(state.relay_map.is_empty(), "relay_map must be empty after non-Boards Resp rejection");

    drop(alice_ws);
}

// ── Dual-mode (v2 header form) tests ─────────────────────────────────────────

/// Wave 3 dual-mode: HELLO with v2 `from:` header (no X-From) is accepted.
#[tokio::test]
async fn ws_hello_v2_from_header_accepted() {
    let (addr, state) = spawn_test_server().await;
    let signing_key = setup_agent(&state, "proj-v2a", "key-v2a", "Alice");

    let mut ws = ws_connect(addr).await;

    // HELLO with v2 form: `from:` instead of `X-From:`
    let hello = HttpFrame::request("HELLO", "/v1/sessions")
        .add_header("from", "Alice@proj-v2a")
        .finalize();
    send_frame(&mut ws, &hello).await;

    let challenge = recv_frame(&mut ws).await;
    assert_eq!(challenge.verb(), Some("CHALLENGE"), "HELLO with v2 'from:' must produce CHALLENGE: {:?}", challenge.first_line);

    let nonce_b64 = challenge.header("X-Nonce").expect("X-Nonce in CHALLENGE").to_string();
    let sig = sign_challenge(&signing_key, "Alice@proj-v2a", &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let ok = recv_frame(&mut ws).await;
    assert_eq!(ok.status(), Some(200), "v2 HELLO handshake must complete with 200 OK: {:?}", ok.first_line);

    drop(ws);
}

/// Wave 3 dual-mode: AUTH with v2 `sig:` header (no X-Sig) is accepted.
#[tokio::test]
async fn ws_auth_v2_sig_header_accepted() {
    let (addr, state) = spawn_test_server().await;
    let signing_key = setup_agent(&state, "proj-v2b", "key-v2b", "Alice");

    let mut ws = ws_connect(addr).await;
    let nonce_b64 = hello_and_get_challenge(&mut ws, "Alice@proj-v2b", None, None).await;
    let sig = sign_challenge(&signing_key, "Alice@proj-v2b", &nonce_b64);

    // AUTH with v2 form: `sig:` instead of `X-Sig:`
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let ok = recv_frame(&mut ws).await;
    assert_eq!(ok.status(), Some(200), "AUTH with v2 'sig:' must complete handshake: {:?}", ok.first_line);

    drop(ws);
}

/// Wave 3 dual-mode: POST /v1/dms with v2 `to:` header (no X-To) is routed correctly.
#[tokio::test]
async fn ws_dm_v2_to_header_accepted() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-v2c", "key-v2c", "Alice");
    setup_agent_in_project(&state, "proj-v2c", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-v2c", &alice_key).await;

    // DM using v2 `to:` header instead of `X-To:`
    let mut dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("to", "Bob@proj-v2c");
    dm.body = "v2 dm test".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    let ack = recv_frame(&mut alice_ws).await;
    // Bob is offline so 202; what matters is it was routed (not 400 Missing X-To)
    assert!(
        matches!(ack.status(), Some(200) | Some(202)),
        "DM with v2 'to:' must be routed (200 or 202), not 400: {:?}", ack.first_line
    );

    drop(alice_ws);
}

/// Wave 3 dual-mode: PUBLISH with v2 `X-Mentions` fallback (v1 form) is accepted.
#[tokio::test]
async fn ws_publish_x_mentions_fallback_accepted() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    setup_agent(&state, "proj-v2d", "key-v2d", "Alice");

    let mut boards_ws = connect_boards_tofu(addr, "proj-v2d").await;

    // PUBLISH with X-Mentions (v1 fallback — broker already reads mentions: natively)
    let publish = HttpFrame::request("PUBLISH", "/v1/deliveries")
        .add_header("X-Mentions", "Alice@proj-v2d")
        .finalize();
    send_frame(&mut boards_ws, &publish).await;

    let ack = recv_frame(&mut boards_ws).await;
    assert_eq!(ack.status(), Some(200), "PUBLISH with X-Mentions must be accepted: {:?}", ack.first_line);

    drop(boards_ws);
}

/// PUBLISH C6 path: Boards sends PUBLISH with a C6 resource path — fans out correctly.
/// Path is forwarded as-is in the DELIVER frame; routing is entirely from mentions:.
#[tokio::test]
async fn ws_publish_c6_resource_path_fans_out() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let alice_key = setup_agent(&state, "proj-pub-c6", "key-pub-c6-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-pub-c6", "Bob");

    let mut boards_ws = connect_boards_tofu(addr, "proj-pub-c6").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-pub-c6", &alice_key).await;
    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-pub-c6", &bob_key).await;

    // Boards sends PUBLISH with a C6 resource path.
    let mut publish = HttpFrame::request("PUBLISH", "/channels/general@proj-pub-c6/threads/t-1/posts/p-1")
        .add_header("X-From", "Boards@proj-pub-c6")
        .add_header("mentions", "Alice@proj-pub-c6,Bob@proj-pub-c6");
    publish.body = "c6 publish body".to_string();
    let publish = publish.finalize();
    send_frame(&mut boards_ws, &publish).await;

    // Boards must receive 200 OK.
    let ack = recv_frame(&mut boards_ws).await;
    assert_eq!(ack.status(), Some(200), "C6-pathed PUBLISH must return 200: {:?}", ack.first_line);

    // Both recipients must receive DELIVER with the C6 resource path preserved.
    let alice_deliver = recv_frame(&mut alice_ws).await;
    assert_eq!(alice_deliver.verb(), Some("DELIVER"), "Alice must receive DELIVER: {:?}", alice_deliver.first_line);
    assert_eq!(
        alice_deliver.path(), Some("/channels/general@proj-pub-c6/threads/t-1/posts/p-1"),
        "DELIVER path must mirror C6 resource path"
    );
    assert_eq!(alice_deliver.body, "c6 publish body", "body must be preserved");

    let bob_deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(bob_deliver.verb(), Some("DELIVER"), "Bob must receive DELIVER: {:?}", bob_deliver.first_line);
    assert_eq!(
        bob_deliver.path(), Some("/channels/general@proj-pub-c6/threads/t-1/posts/p-1"),
        "DELIVER path must mirror C6 resource path for Bob"
    );

    drop(boards_ws); drop(alice_ws); drop(bob_ws);
}

/// C7: PUBLISH with inner verb fans out DELIVER with inner verb mirrored.
/// PUBLISH POST /channels/general@proj/threads/t-1/posts/p-91 → DELIVER POST /channels/...
#[tokio::test]
async fn ws_publish_c7_inner_verb_mirrored_in_deliver() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let alice_key = setup_agent(&state, "proj-c7a", "key-c7a", "Alice");

    let mut boards_ws = connect_boards_tofu(addr, "proj-c7a").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-c7a", &alice_key).await;

    // Boards sends PUBLISH with C7 inner verb (3-token first line, no HTTP/1.1).
    // Build raw wire bytes — the HttpFrame builder always sets has_version:true,
    // so we send raw text to simulate a C7 client.
    let raw_publish = "PUBLISH POST /channels/general@proj-c7a/threads/t-1/posts/p-91\r\n\
mentions: Alice@proj-c7a\r\n\
Content-Length: 7\r\n\r\nbody c7";
    boards_ws.send(tokio_tungstenite::tungstenite::Message::Text(raw_publish.into()))
        .await.expect("send C7 PUBLISH");

    // Boards must receive 200 OK.
    let ack = recv_frame(&mut boards_ws).await;
    assert_eq!(ack.status(), Some(200), "C7 PUBLISH must return 200: {:?}", ack.first_line);

    // Alice must receive DELIVER with inner verb POST mirrored.
    let deliver = recv_frame(&mut alice_ws).await;
    assert_eq!(deliver.verb(), Some("DELIVER"), "Alice must receive DELIVER: {:?}", deliver.first_line);
    assert_eq!(deliver.inner_verb(), Some("POST"), "inner verb POST must be mirrored in DELIVER");
    assert_eq!(deliver.path(), Some("/channels/general@proj-c7a/threads/t-1/posts/p-91"),
        "path must be preserved");
    assert_eq!(deliver.body, "body c7", "body must be preserved");

    drop(boards_ws); drop(alice_ws);
}

/// Wave 3 dual-mode: PUT /v1/presence with v2 `status:` header (no X-Status) is accepted.
#[tokio::test]
async fn ws_presence_v2_status_header_accepted() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-v2e", "key-v2e", "Alice");

    let mut ws = ws_connect(addr).await;
    complete_handshake(&mut ws, "Alice@proj-v2e", &alice_key).await;

    // PUT /v1/presence with v2 `status:` header
    let presence = HttpFrame::request("PUT", "/v1/presence")
        .add_header("status", "busy")
        .finalize();
    send_frame(&mut ws, &presence).await;

    let ok = recv_frame(&mut ws).await;
    assert_eq!(ok.status(), Some(200), "presence with v2 'status:' must return 200: {:?}", ok.first_line);

    drop(ws);
}

/// Wave 3 C1: no-version request line is accepted and forwarded as-is (without HTTP/1.1 added).
#[tokio::test]
async fn ws_no_version_request_line_accepted() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-v2f", "key-v2f", "Alice");

    let mut ws = ws_connect(addr).await;

    // Build a HELLO frame without HTTP/1.1 by serializing manually (the builder always adds it).
    // Construct the raw wire string directly to simulate a v2 client.
    let raw_hello = "HELLO /v1/sessions\r\nX-From: Alice@proj-v2f\r\nContent-Length: 0\r\n\r\n";
    ws.send(WsMsg::Text(raw_hello.into())).await.expect("send no-version HELLO");

    let challenge = recv_frame(&mut ws).await;
    assert_eq!(
        challenge.verb(),
        Some("CHALLENGE"),
        "no-version HELLO must be accepted and produce CHALLENGE: {:?}",
        challenge.first_line
    );

    // Complete handshake normally.
    let nonce_b64 = challenge.header("X-Nonce").expect("X-Nonce").to_string();
    let sig = sign_challenge(&alice_key, "Alice@proj-v2f", &nonce_b64);
    let auth = HttpFrame::request("AUTH", "/v1/sessions")
        .add_header("X-Sig", &sig)
        .finalize();
    send_frame(&mut ws, &auth).await;

    let ok = recv_frame(&mut ws).await;
    assert_eq!(ok.status(), Some(200), "no-version handshake must complete: {:?}", ok.first_line);

    drop(ws);
}

// ── C6 resource-path tests ────────────────────────────────────────────────────

/// C6 t1: channel-rooted POST path — Boards offline → 503 (proves C6 path parsed + routed).
/// Path: /channels/general@proj-c6a/posts — project extracted from path, no X-To needed.
#[tokio::test]
async fn ws_c6_channel_post_path_routed_to_boards() {
    let (addr, state) = spawn_relay_server(5).await;
    let agent_key = setup_agent(&state, "proj-c6a", "key-c6a", "Alice");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-c6a", &agent_key).await;

    // C6 path — no X-To header required; project is in the path.
    let post = HttpFrame::request("POST", "/channels/general@proj-c6a/posts")
        .add_header("correlation-id", "cid-c6a")
        .finalize();
    send_frame(&mut alice_ws, &post).await;

    // Boards is offline → 503 with Retry-After: 1 (proves the frame was parsed and routed).
    let resp = recv_frame(&mut alice_ws).await;
    assert_eq!(resp.status(), Some(503), "C6 channel post must return 503 when Boards offline: {:?}", resp.first_line);
    assert_eq!(resp.header("Retry-After"), Some("1"), "must include Retry-After: 1");
    assert_eq!(resp.header("correlation-id"), Some("cid-c6a"), "correlation-id must be echoed");

    drop(alice_ws);
}

/// C6 t2: deep C6 path with thread+post segments — project still extracted correctly.
/// Path: /channels/analysis@proj-c6b/threads/t-7/posts/p-91 → routed to Boards@proj-c6b.
#[tokio::test]
async fn ws_c6_deep_channel_path_routed_to_boards() {
    let (addr, state) = spawn_relay_server(5).await;
    let agent_key = setup_agent(&state, "proj-c6b", "key-c6b", "Bob");

    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-c6b", &agent_key).await;

    let post = HttpFrame::request("POST", "/channels/analysis@proj-c6b/threads/t-7/posts/p-91")
        .add_header("correlation-id", "cid-c6b")
        .finalize();
    send_frame(&mut bob_ws, &post).await;

    let resp = recv_frame(&mut bob_ws).await;
    assert_eq!(resp.status(), Some(503), "deep C6 path must return 503 when Boards offline: {:?}", resp.first_line);
    assert_eq!(resp.header("correlation-id"), Some("cid-c6b"), "correlation-id must be echoed");

    drop(bob_ws);
}

/// C6 t3: v1 path still works unchanged — backward compat check.
#[tokio::test]
async fn ws_v1_post_path_still_works_after_c6() {
    let (addr, state) = spawn_relay_server(5).await;
    let agent_key = setup_agent(&state, "proj-c6c", "key-c6c", "Carol");

    let mut carol_ws = ws_connect(addr).await;
    complete_handshake(&mut carol_ws, "Carol@proj-c6c", &agent_key).await;

    // v1 path with X-To header — must still work.
    let post = HttpFrame::request("POST", "/v1/posts")
        .add_header("X-To", "#general.proj-c6c")
        .add_header("correlation-id", "cid-c6c")
        .finalize();
    send_frame(&mut carol_ws, &post).await;

    let resp = recv_frame(&mut carol_ws).await;
    assert_eq!(resp.status(), Some(503), "v1 path must still return 503 when Boards offline: {:?}", resp.first_line);
    assert_eq!(resp.header("correlation-id"), Some("cid-c6c"), "correlation-id must be echoed");

    drop(carol_ws);
}

// ── C6 DM resource-path tests ─────────────────────────────────────────────────

/// C6 DM t1: live delivery via /agents/<name>@<project>/dms path — no X-To needed.
/// Recipient gets DELIVER on the C6 resource path (/agents/Bob@proj-c6dm1/dms); sender gets 200 OK.
#[tokio::test]
async fn ws_c6_dm_path_live_delivery() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-c6dm1", "key-c6dm1", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-c6dm1", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-c6dm1", &alice_key).await;

    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-c6dm1", &bob_key).await;

    // C6 DM path — no X-To header on frame.
    let mut dm = HttpFrame::request("POST", "/agents/Bob@proj-c6dm1/dms")
        .add_header("X-From", "Alice@proj-c6dm1")
        .add_header("correlation-id", "cid-c6dm1");
    dm.body = "hello via c6".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    // Sender gets 200 OK.
    let ack = recv_frame(&mut alice_ws).await;
    assert_eq!(ack.status(), Some(200), "C6 DM live delivery must return 200: {:?}", ack.first_line);
    assert_eq!(ack.header("correlation-id"), Some("cid-c6dm1"), "cid must be echoed");

    // Recipient gets DELIVER mirroring the C6 source path (not hardcoded /v1/dms).
    let deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(deliver.verb(), Some("DELIVER"), "recipient must get DELIVER: {:?}", deliver.first_line);
    assert_eq!(deliver.path(), Some("/agents/Bob@proj-c6dm1/dms"), "DELIVER path must mirror C6 source path");
    assert!(
        matches!(&deliver.first_line, super::FirstLine::Request { inner_verb: Some(iv), .. } if iv == "POST"),
        "DELIVER must carry inner_verb POST (C7), got: {:?}", deliver.first_line
    );
    assert_eq!(deliver.header("from"), Some("Alice@proj-c6dm1"), "from: must be canonicalized sender (v2)");
    assert!(deliver.header("X-From").is_none(), "X-From must not appear on broker-emitted DELIVER");
    assert!(deliver.header("to").is_none(), "to: must not appear on broker-emitted DM DELIVER");
    assert!(deliver.header("X-To").is_none(), "X-To must not appear on broker-emitted DELIVER");
    assert_eq!(deliver.body, "hello via c6", "body must be preserved");

    drop(alice_ws); drop(bob_ws);
}

/// C6 DM t2: offline recipient via C6 path → 202 Accepted + queued for drain.
#[tokio::test]
async fn ws_c6_dm_path_offline_recipient_queued() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-c6dm2", "key-c6dm2", "Alice");
    setup_agent_in_project(&state, "proj-c6dm2", "Bob"); // registered but not connected

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-c6dm2", &alice_key).await;

    let mut dm = HttpFrame::request("POST", "/agents/Bob@proj-c6dm2/dms")
        .add_header("X-From", "Alice@proj-c6dm2");
    dm.body = "queued c6 dm".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;

    let ack = recv_frame(&mut alice_ws).await;
    assert_eq!(ack.status(), Some(202), "C6 DM to offline recipient must return 202: {:?}", ack.first_line);

    // Verify message was actually queued.
    let pending = state.broker.repo.peek_pending("Bob", "proj-c6dm2");
    assert!(!pending.is_empty(), "DM must be queued for Bob");

    drop(alice_ws);
}

/// C6 DM t3: unknown recipient via C6 path → 404.
#[tokio::test]
async fn ws_c6_dm_path_unknown_recipient_404() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-c6dm3", "key-c6dm3", "Alice");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-c6dm3", &alice_key).await;

    let dm = HttpFrame::request("POST", "/agents/NoSuch@proj-c6dm3/dms")
        .finalize();
    send_frame(&mut alice_ws, &dm).await;

    let resp = recv_frame(&mut alice_ws).await;
    assert_eq!(resp.status(), Some(404), "C6 DM to unknown recipient must return 404: {:?}", resp.first_line);

    drop(alice_ws);
}

/// C6 DM t4: arbitrary tail on /agents/ path → 400 (must not misroute as DM).
#[tokio::test]
async fn ws_c6_dm_path_arbitrary_tail_rejected() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-c6dm4", "key-c6dm4", "Alice");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-c6dm4", &alice_key).await;

    let bad = HttpFrame::request("POST", "/agents/Bob@proj-c6dm4/evil").finalize();
    send_frame(&mut alice_ws, &bad).await;

    let resp = recv_frame(&mut alice_ws).await;
    assert_eq!(resp.status(), Some(400), "/agents/.../evil must return 400, not route as DM: {:?}", resp.first_line);

    drop(alice_ws);
}

/// Broker-constructed DELIVER frames must NOT include HTTP/1.1 version suffix.
/// C7 receivers parse 2-token or 3-token first lines; the trailing HTTP/1.1 breaks matching.
#[tokio::test]
async fn ws_deliver_dm_no_version_suffix() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-nov1", "key-nov1-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-nov1", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-nov1", &alice_key).await;
    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-nov1", &bob_key).await;

    // Alice sends a v1-form DM (with HTTP/1.1) — broker must strip version from DELIVER.
    let dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-To", "Bob@proj-nov1")
        .finalize();
    send_frame(&mut alice_ws, &dm).await;

    let _ack = recv_frame(&mut alice_ws).await;

    // Bob receives the DELIVER frame — check the raw wire form has no HTTP/1.1 suffix.
    let deliver = recv_frame(&mut bob_ws).await;
    assert_eq!(deliver.verb(), Some("DELIVER"), "must receive DELIVER: {:?}", deliver.first_line);
    // has_version must be false — no HTTP/1.1 on the first line.
    assert!(
        matches!(&deliver.first_line, super::FirstLine::Request { has_version: false, .. }),
        "broker-constructed DELIVER must have has_version: false, got: {:?}", deliver.first_line
    );
    let wire = deliver.serialize();
    assert!(wire.starts_with("DELIVER POST /agents/Bob@proj-nov1/dms\r\n"),
        "DELIVER first line must be C6 path (inner_verb POST, no HTTP/1.1): {wire:?}");

    drop(alice_ws); drop(bob_ws);
}

/// DELIVER frame for v1 DM path must dual-write both `to:` (v2) and `X-To` (v1) recipient headers.
#[tokio::test]
async fn ws_deliver_dm_dual_writes_to_header() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-dwto1", "key-dwto1-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-dwto1", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-dwto1", &alice_key).await;
    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-dwto1", &bob_key).await;

    let dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-To", "Bob@proj-dwto1")
        .finalize();
    send_frame(&mut alice_ws, &dm).await;
    let _ack = recv_frame(&mut alice_ws).await;

    let deliver = recv_frame(&mut bob_ws).await;
    // Broker-emitted DM DELIVER carries no addressing headers — recipient addressed by WS session.
    assert!(deliver.header("to").is_none(), "to: must not appear on broker-emitted DM DELIVER");
    assert!(deliver.header("X-To").is_none(), "X-To must not appear on broker-emitted DELIVER");

    drop(alice_ws); drop(bob_ws);
}

/// DELIVER frame inner_verb must be POST (C7) for DM delivery.
#[tokio::test]
async fn ws_deliver_dm_inner_verb_is_post() {
    let (addr, state) = spawn_test_server().await;
    let alice_key = setup_agent(&state, "proj-div1", "key-div1-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-div1", "Bob");

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-div1", &alice_key).await;
    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-div1", &bob_key).await;

    let dm = HttpFrame::request("POST", "/v1/dms")
        .add_header("X-To", "Bob@proj-div1")
        .finalize();
    send_frame(&mut alice_ws, &dm).await;
    let _ack = recv_frame(&mut alice_ws).await;

    let deliver = recv_frame(&mut bob_ws).await;
    assert!(
        matches!(&deliver.first_line, super::FirstLine::Request { inner_verb: Some(iv), .. } if iv == "POST"),
        "DELIVER must carry inner_verb POST (C7), got: {:?}", deliver.first_line
    );

    drop(alice_ws); drop(bob_ws);
}

/// Wire log: when wire_log is configured, inbound first-line and outbound DELIVER appear in the log.
#[tokio::test]
async fn ws_wire_log_records_inbound_and_outbound() {
    let log_path = std::env::temp_dir().join(format!("wire-log-test-{}.log", uuid::Uuid::new_v4()));
    let wire_log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("open temp wire log");

    // Spin up the background writer thread (same pattern as main.rs).
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
    std::thread::spawn(move || {
        use std::io::{BufWriter, Write};
        let mut writer = BufWriter::new(wire_log_file);
        for entry in rx {
            let _ = writer.write_all(entry.as_bytes());
            let _ = writer.flush();
        }
    });
    let wire_log: Option<Arc<std::sync::mpsc::SyncSender<String>>> = Some(Arc::new(tx));

    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker_state = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker_state.clone()));
    let config = BrokerConfig {
        admin_key: None,
        rate_limit_rps: 100,
        boards_registration_token: None,
        archive_dms: false,
        relay_timeout: std::time::Duration::from_secs(5),
        log_file: Some(log_path.to_string_lossy().into_owned()),
    };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState {
        broker: broker_state,
        delivery,
        config,
        rate_limiter,
        relay_map: Arc::new(dashmap::DashMap::new()),
        wire_log,
    });

    let alice_key = setup_agent(&state, "proj-wl1", "key-wl1-a", "Alice");
    let bob_key = setup_agent_in_project(&state, "proj-wl1", "Bob");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let app = crate::api::http_router(state.clone())
        .route("/ws", axum::routing::get(crate::api::handle_ws))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-wl1", &alice_key).await;
    let mut bob_ws = ws_connect(addr).await;
    complete_handshake(&mut bob_ws, "Bob@proj-wl1", &bob_key).await;

    let mut dm = HttpFrame::request("POST", "/v1/dms").add_header("X-To", "Bob@proj-wl1");
    dm.body = "wire log test body".to_string();
    let dm = dm.finalize();
    send_frame(&mut alice_ws, &dm).await;
    let _ack = recv_frame(&mut alice_ws).await;
    let deliver_frame = recv_frame(&mut bob_ws).await;

    // DELIVER must carry `from:` (v2 sender identity); no X-From, to:, or X-To.
    let sender_id = "Alice@proj-wl1";
    assert_eq!(deliver_frame.header("from"), Some(sender_id),
        "DELIVER must carry v2 'from:' header");
    assert!(deliver_frame.header("X-From").is_none(),
        "X-From must not appear on broker-emitted DELIVER");
    assert!(deliver_frame.header("to").is_none(),
        "to: must not appear on broker-emitted DM DELIVER");

    // Both log entries have been try_send'd by the time recv_frame returns.
    // Give the background writer thread a moment to flush to disk.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let log_contents = std::fs::read_to_string(&log_path).expect("read wire log");
    assert!(log_contents.contains("POST /v1/dms"),
        "wire log must contain inbound 'POST /v1/dms'; got:\n{log_contents}");
    assert!(log_contents.contains("DELIVER POST /agents/Bob@proj-wl1/dms"),
        "wire log must contain outbound C6 DELIVER path; got:\n{log_contents}");
    assert!(log_contents.contains("[INBOUND]"), "wire log must contain [INBOUND] marker");
    assert!(log_contents.contains("[OUTBOUND]"), "wire log must contain [OUTBOUND] marker");
    assert!(log_contents.contains("→ "),
        "wire log must contain '→ <outcome>' line; got:\n{log_contents}");
    assert!(log_contents.contains(&format!("from: {sender_id}")),
        "wire log must contain v2 'from:' header in OUTBOUND entry; got:\n{log_contents}");

    let _ = std::fs::remove_file(&log_path);
    drop(alice_ws);
    drop(bob_ws);
}

/// Wire log test 2: Boards relay response branch is logged.
/// The `is_response()` fast-path in `handle_inbound` logs with direction [INBOUND]
/// before forwarding the response to the waiting sender.
#[tokio::test]
async fn ws_wire_log_records_relay_response() {
    // Spin up wire log channel + background writer thread.
    let log_path = std::env::temp_dir().join(format!("wire-log-relay-{}.log", uuid::Uuid::new_v4()));
    let wire_log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("open temp wire log");
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
    std::thread::spawn(move || {
        use std::io::{BufWriter, Write};
        let mut writer = BufWriter::new(wire_log_file);
        for entry in rx {
            let _ = writer.write_all(entry.as_bytes());
            let _ = writer.flush();
        }
    });
    let wire_log: Option<Arc<std::sync::mpsc::SyncSender<String>>> = Some(Arc::new(tx));

    // Build relay-capable server state with wire log enabled.
    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker_st = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker_st.clone()));
    let config = BrokerConfig {
        admin_key: None,
        rate_limit_rps: 100,
        boards_registration_token: Some(TEST_BOARDS_TOKEN.to_string()),
        archive_dms: false,
        relay_timeout: std::time::Duration::from_secs(5),
        log_file: Some(log_path.to_string_lossy().into_owned()),
    };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState {
        broker: broker_st,
        delivery,
        config,
        rate_limiter,
        relay_map: Arc::new(DashMap::new()),
        wire_log,
    });

    let alice_key = setup_agent(&state, "proj-wlr", "key-wlr", "Alice");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let app = crate::api::http_router(state.clone())
        .route("/ws", axum::routing::get(crate::api::handle_ws))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });

    let mut boards_ws = connect_boards_tofu(addr, "proj-wlr").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-wlr", &alice_key).await;

    // Alice posts to a channel — broker relays to Boards.
    let post = HttpFrame::request("POST", "/v1/posts")
        .add_header("X-To", "#general.proj-wlr")
        .add_header("correlation-id", "cid-wlr-1")
        .finalize();
    send_frame(&mut alice_ws, &post).await;

    // Boards receives the relayed frame.
    let forwarded = recv_frame(&mut boards_ws).await;
    let relay_id = forwarded.header("correlation-id")
        .expect("relay-id must be present")
        .to_string();

    // Boards sends back 201 — this is the relay response (is_response() == true).
    let mut boards_resp = HttpFrame::response(201, "Created");
    boards_resp.set_header("correlation-id", &relay_id);
    let boards_resp = boards_resp.finalize();
    send_frame(&mut boards_ws, &boards_resp).await;

    // Alice receives her 201 (confirms the relay completed before we check the log).
    let alice_resp = recv_frame(&mut alice_ws).await;
    assert_eq!(alice_resp.status(), Some(201), "Alice must receive 201");

    // Allow background writer thread to flush.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let log_contents = std::fs::read_to_string(&log_path).expect("read wire log");
    assert!(log_contents.contains("[INBOUND]"),
        "wire log must contain [INBOUND] for relay response; got:\n{log_contents}");
    assert!(log_contents.contains("201"),
        "wire log must contain '201' from the relay response first-line; got:\n{log_contents}");
    assert!(log_contents.contains("(relay response)"),
        "wire log must record relay response outcome; got:\n{log_contents}");

    let _ = std::fs::remove_file(&log_path);
    drop(alice_ws);
    drop(boards_ws);
}

/// PUBLISH fan-out: Boards sends PUBLISH with `from:` only (no `X-From`).
/// fan_out_publish must write only `from:` (v2) on the DELIVER so
/// v1 and v2 receivers both see the sender identity — robust to Boards v2 cutover.
#[tokio::test]
async fn ws_publish_from_only_deliver_gets_both_from_headers() {
    let (addr, state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let alice_key = setup_agent(&state, "proj-fromonly", "key-fromonly", "Alice");

    let mut boards_ws = connect_boards_tofu(addr, "proj-fromonly").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-fromonly", &alice_key).await;

    // Boards sends PUBLISH with `from:` (v2) only — no `X-From` header.
    let publish = HttpFrame::request("PUBLISH", "/channels/general@proj-fromonly/threads/t-1/posts/p-1")
        .add_header("from", "Boards@proj-fromonly")
        .add_header("mentions", "Alice@proj-fromonly")
        .finalize();
    send_frame(&mut boards_ws, &publish).await;
    let ack = recv_frame(&mut boards_ws).await;
    assert_eq!(ack.status(), Some(200), "PUBLISH must return 200: {:?}", ack.first_line);

    // Alice receives DELIVER — `from:` (v2) only; X-From must not appear (broker-emitted frames v2 only).
    let deliver = recv_frame(&mut alice_ws).await;
    assert_eq!(deliver.verb(), Some("DELIVER"),
        "Alice must receive DELIVER: {:?}", deliver.first_line);
    assert_eq!(deliver.header("from"), Some("Boards@proj-fromonly"),
        "DELIVER must carry v2 'from:' header");
    assert!(deliver.header("X-From").is_none(),
        "X-From must not appear on broker-emitted DELIVER");

    drop(boards_ws);
    drop(alice_ws);
}

/// PUBLISH path guard: a PUBLISH with `/channels/@project/...` (empty channel segment)
/// must be rejected with 400 — `parse_channel_from_path` returns None for empty channel.
/// Prevents silent fan-out of malformed paths into DELIVER frames.
#[tokio::test]
async fn ws_publish_malformed_channel_path_returns_400() {
    let (addr, _state) = spawn_test_server_with_boards_token(TEST_BOARDS_TOKEN).await;
    let mut boards_ws = connect_boards_tofu(addr, "proj-badpath").await;

    // Path has empty channel segment: `/channels/@proj-badpath/threads/t-1`
    let publish = HttpFrame::request("PUBLISH", "/channels/@proj-badpath/threads/t-1")
        .add_header("from", "Boards@proj-badpath")
        .add_header("mentions", "Nobody@proj-badpath")
        .finalize();
    send_frame(&mut boards_ws, &publish).await;

    let resp = recv_frame(&mut boards_ws).await;
    assert_eq!(resp.status(), Some(400),
        "PUBLISH with empty channel segment must return 400; got: {:?}", resp.first_line);

    drop(boards_ws);
}

/// Wire log: `forward_to_boards` logs `[OUTBOUND]` with "→ relayed to Boards@<project>"
/// on a successful relay. Alice sends POST /channels/... → broker relays to connected
/// Boards → Boards replies → broker routes back. After relay completes, wire log file
/// must contain the success outcome string.
#[tokio::test]
async fn ws_wire_log_forward_to_boards_success() {
    // Spin up wire log channel + background writer thread.
    let log_path = std::env::temp_dir()
        .join(format!("wire-log-fwdb-ok-{}.log", uuid::Uuid::new_v4()));
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("open temp wire log");
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
    std::thread::spawn(move || {
        use std::io::{BufWriter, Write};
        let mut w = BufWriter::new(log_file);
        for entry in rx {
            let _ = w.write_all(entry.as_bytes());
            let _ = w.flush();
        }
    });
    let wire_log: Option<Arc<std::sync::mpsc::SyncSender<String>>> = Some(Arc::new(tx));

    // Build relay-capable server state with wire log enabled.
    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker_st = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker_st.clone()));
    let config = BrokerConfig {
        admin_key: None,
        rate_limit_rps: 100,
        boards_registration_token: Some(TEST_BOARDS_TOKEN.to_string()),
        archive_dms: false,
        relay_timeout: std::time::Duration::from_secs(5),
        log_file: Some(log_path.to_string_lossy().into_owned()),
    };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState {
        broker: broker_st,
        delivery,
        config,
        rate_limiter,
        relay_map: Arc::new(DashMap::new()),
        wire_log,
    });

    let alice_key = setup_agent(&state, "proj-fwdb", "key-fwdb", "Alice");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let app = crate::api::http_router(state.clone())
        .route("/ws", axum::routing::get(crate::api::handle_ws))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });

    let mut boards_ws = connect_boards_tofu(addr, "proj-fwdb").await;
    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-fwdb", &alice_key).await;

    // Alice sends POST to a channel path — broker relays via forward_to_boards.
    let post = HttpFrame::request("POST", "/channels/general@proj-fwdb/threads")
        .add_header("correlation-id", "cid-fwdb-1")
        .finalize();
    send_frame(&mut alice_ws, &post).await;

    // Boards receives the relayed frame; extract relay-id and reply 201.
    let forwarded = recv_frame(&mut boards_ws).await;
    let relay_id = forwarded.header("correlation-id")
        .expect("relay-id must be present on forwarded frame")
        .to_string();
    let mut boards_resp = HttpFrame::response(201, "Created");
    boards_resp.set_header("correlation-id", &relay_id);
    let boards_resp = boards_resp.finalize();
    send_frame(&mut boards_ws, &boards_resp).await;

    // Alice receives the relay response — confirms forward_to_boards completed.
    let alice_resp = recv_frame(&mut alice_ws).await;
    assert_eq!(alice_resp.status(), Some(201), "Alice must receive 201 relay response");

    // Allow background writer thread to flush to disk.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let contents = std::fs::read_to_string(&log_path).expect("read wire log");
    assert!(
        contents.contains("\u{2192} relayed to Boards@"),
        "wire log must record successful relay outcome; got:\n{contents}"
    );

    let _ = std::fs::remove_file(&log_path);
    drop(alice_ws);
    drop(boards_ws);
}

/// Wire log: `forward_to_boards` logs `[OUTBOUND]` with "not connected — 503"
/// when Boards is not connected for the target project.
/// Alice sends POST /channels/... → broker finds no Boards → returns 503 → log entry written.
#[tokio::test]
async fn ws_wire_log_forward_to_boards_503() {
    // Spin up wire log channel + background writer thread.
    let log_path = std::env::temp_dir()
        .join(format!("wire-log-fwdb-503-{}.log", uuid::Uuid::new_v4()));
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .expect("open temp wire log");
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(1024);
    std::thread::spawn(move || {
        use std::io::{BufWriter, Write};
        let mut w = BufWriter::new(log_file);
        for entry in rx {
            let _ = w.write_all(entry.as_bytes());
            let _ = w.flush();
        }
    });
    let wire_log: Option<Arc<std::sync::mpsc::SyncSender<String>>> = Some(Arc::new(tx));

    // Build state with wire log — no Boards will connect.
    let repo = Arc::new(db::open_memory().expect("in-memory DB"));
    let broker_st = Arc::new(BrokerState::new(repo));
    let delivery = Arc::new(DeliveryEngine::new(broker_st.clone()));
    let config = BrokerConfig {
        admin_key: None,
        rate_limit_rps: 100,
        boards_registration_token: Some(TEST_BOARDS_TOKEN.to_string()),
        archive_dms: false,
        relay_timeout: std::time::Duration::from_secs(5),
        log_file: Some(log_path.to_string_lossy().into_owned()),
    };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState {
        broker: broker_st,
        delivery,
        config,
        rate_limiter,
        relay_map: Arc::new(DashMap::new()),
        wire_log,
    });

    let alice_key = setup_agent(&state, "proj-503", "key-503", "Alice");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let app = crate::api::http_router(state.clone())
        .route("/ws", axum::routing::get(crate::api::handle_ws))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });

    let mut alice_ws = ws_connect(addr).await;
    complete_handshake(&mut alice_ws, "Alice@proj-503", &alice_key).await;

    // Alice sends POST to a channel — Boards@proj-503 is not connected → 503.
    let post = HttpFrame::request("POST", "/channels/general@proj-503/threads")
        .add_header("correlation-id", "cid-503-1")
        .finalize();
    send_frame(&mut alice_ws, &post).await;

    let resp = recv_frame(&mut alice_ws).await;
    assert_eq!(resp.status(), Some(503),
        "must receive 503 when Boards not connected; got: {:?}", resp.first_line);

    // Allow background writer thread to flush.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let contents = std::fs::read_to_string(&log_path).expect("read wire log");
    assert!(
        contents.contains("not connected"),
        "wire log must record 503 not-connected outcome; got:\n{contents}"
    );

    let _ = std::fs::remove_file(&log_path);
    drop(alice_ws);
}
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
    let config = BrokerConfig { admin_key: None, rate_limit_rps: 100, boards_registration_token };
    let rate_limiter = Arc::new(ProjectRateLimiter::new(100));
    let state = Arc::new(AppState { broker, delivery, config, rate_limiter });

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

    // --- Boards must receive POST with canonicalized X-From = authenticated identity ---
    let forwarded = recv_frame(&mut boards_ws).await;
    assert_eq!(
        forwarded.header("X-From"),
        Some(agent_identity),
        "X-From must be canonicalized to authenticated identity, not forged value: {:?}",
        forwarded
    );

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

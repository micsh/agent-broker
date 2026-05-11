use crate::identity::{self, Identity};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};

// Type aliases for the split WS halves produced by tokio_tungstenite::connect_async.
pub type WsTx =
    futures_util::stream::SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
pub type WsRx = futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// Extract a named header value from a raw HttpFrame text (case-insensitive).
pub fn extract_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    let name_lower = name.to_ascii_lowercase();
    for line in raw.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            if line[..colon].trim().to_ascii_lowercase() == name_lower {
                return Some(line[colon + 1..].trim());
            }
        }
    }
    None
}

/// Receive the next text WS message. `context` is used only in error messages.
async fn recv_text(rx: &mut WsRx, context: &str) -> Result<String> {
    let msg = rx
        .next()
        .await
        .ok_or_else(|| anyhow!("connection closed before {context}"))??;
    match msg {
        Message::Text(t) => Ok(t.to_string()),
        Message::Close(c) => bail!(
            "connection closed during {context}: {:?}",
            c.map(|f| f.reason.to_string())
        ),
        _ => bail!("unexpected non-text message during {context}"),
    }
}

/// Perform HELLO → CHALLENGE → AUTH.
/// Returns `(tx, rx, ok_raw)` where `ok_raw` is the raw 200 OK response frame.
/// Callers can extract headers from `ok_raw` (e.g. `X-Pending-Count`).
pub async fn handshake(
    id: &Identity,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(WsTx, WsRx, String)> {
    let url = id.ws_url();
    let (ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .with_context(|| format!("ws connect to {url}"))?;
    let (mut tx, mut rx) = ws.split();

    let identity_str = id.fq();

    // ── HELLO ────────────────────────────────────────────────────────────────
    let hello = format!("HELLO /v1/sessions\r\nfrom: {identity_str}\r\n\r\n");
    tx.send(Message::Text(hello.into())).await?;

    // ── CHALLENGE ────────────────────────────────────────────────────────────
    let challenge_raw = recv_text(&mut rx, "CHALLENGE").await?;
    let first_line = challenge_raw.split("\r\n").next().unwrap_or("");
    if !first_line.starts_with("CHALLENGE ") {
        bail!("expected CHALLENGE, got: {}", first_line);
    }
    let nonce_b64 = extract_header(&challenge_raw, "X-Nonce")
        .ok_or_else(|| anyhow!("CHALLENGE frame missing X-Nonce header"))?;

    // ── AUTH ─────────────────────────────────────────────────────────────────
    // Canonical payload: "AITEAM-AUTH-v1\n{name@project}\n{base64_nonce}"
    let payload = format!("AITEAM-AUTH-v1\n{identity_str}\n{nonce_b64}");
    let signature = signing_key.sign(payload.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let auth = format!("AUTH /v1/sessions\r\nX-Sig: {sig_b64}\r\n\r\n");
    tx.send(Message::Text(auth.into())).await?;

    // ── 200 OK ───────────────────────────────────────────────────────────────
    let ok_raw = recv_text(&mut rx, "auth response").await?;
    let ok_first = ok_raw.split("\r\n").next().unwrap_or("");
    // Status line: "HTTP/1.1 200 OK" — code is the second whitespace token.
    let status_code = ok_first.split_whitespace().nth(1).unwrap_or("");
    if status_code != "200" {
        bail!("auth failed: {}", ok_first);
    }

    Ok((tx, rx, ok_raw))
}

/// Connect, authenticate, send one frame over WS, read the response, disconnect.
///
/// After sending, reads frames until an HTTP status response is found, discarding
/// any DELIVER frames that may arrive concurrently (e.g. pending stored messages).
/// Returns `Ok(())` on 2xx, error otherwise.
pub async fn send_one(id: &Identity, frame: String) -> Result<()> {
    let signing_key = identity::load_ed25519_key(&id.project, &id.name).ok_or_else(|| {
        anyhow!(
            "no Ed25519 key for {}. Run `broker register` first.",
            id.fq()
        )
    })?;

    let (mut tx, mut rx, _ok_raw) = handshake(id, &signing_key).await?;

    tx.send(Message::Text(frame.into())).await?;

    // Loop until we see a status response (first line starts with "HTTP/").
    // Skip any DELIVER or other request frames that may arrive first (e.g. pending messages).
    loop {
        match rx.next().await {
            Some(Ok(Message::Text(t))) => {
                let first = t.split("\r\n").next().unwrap_or("");
                if first.starts_with("HTTP/") {
                    let status = first.split_whitespace().nth(1).unwrap_or("");
                    let _ = tx.close().await;
                    if status.starts_with('2') {
                        return Ok(());
                    }
                    bail!("send failed ({}): {}", status, first);
                }
                // Non-status frame (DELIVER etc.) — skip.
            }
            Some(Ok(_)) => {} // binary / ping / pong — skip
            Some(Err(e)) => bail!("ws error waiting for send response: {e}"),
            None => bail!("connection closed before send response"),
        }
    }
}

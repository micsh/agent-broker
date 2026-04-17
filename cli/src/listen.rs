use crate::identity::Identity;
use anyhow::{Context, Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use regex::Regex;
use serde_json::{Value, json};
use std::io::Write;
use std::sync::OnceLock;
use tokio_tungstenite::tungstenite::Message;

fn attr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(\w[\w-]*)="([^"]*)""#).unwrap())
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn emit(v: Value) {
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    let _ = writeln!(h, "{}", serde_json::to_string(&v).unwrap());
    let _ = h.flush();
}

/// Parse the opening tag of a stanza into an NDJSON event.
/// Mirrors broker/src/stanza/parser.rs: only the opening tag's attrs are inspected; body is opaque.
fn stanza_to_json(raw: &str) -> Value {
    let trimmed = raw.trim_start();
    let open_end = trimmed.find('>').unwrap_or(trimmed.len());
    let open = &trimmed[..open_end];

    let mut obj = serde_json::Map::new();
    let event = if trimmed.starts_with("<message") {
        "message"
    } else if trimmed.starts_with("<presence") {
        "presence"
    } else {
        "stanza"
    };
    obj.insert("event".into(), json!(event));
    for cap in attr_re().captures_iter(open) {
        obj.insert(cap[1].to_string(), json!(cap[2].to_string()));
    }
    obj.insert("raw".into(), json!(raw));
    obj.insert("ts".into(), json!(now()));
    Value::Object(obj)
}

/// One WS session: connect (legacy project_key envelope), drain pending, stream until close/error.
async fn session(id: &Identity, key: &str) -> Result<()> {
    let url = id.ws_url();
    let (ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .with_context(|| format!("ws connect to {url}"))?;
    let (mut tx, mut rx) = ws.split();

    let connect = json!({
        "type": "connect",
        "name": id.name,
        "project": id.project,
        "project_key": key,
    });
    tx.send(Message::Text(connect.to_string().into())).await?;

    while let Some(frame) = rx.next().await {
        let msg = frame?;
        match msg {
            Message::Text(t) => {
                let s = t.as_str();
                if s.trim_start().starts_with('<') {
                    emit(stanza_to_json(s));
                } else if let Ok(env) = serde_json::from_str::<Value>(s) {
                    match env.get("type").and_then(|v| v.as_str()) {
                        Some("connected") => emit(json!({
                            "event": "connected",
                            "as": id.fq(),
                            "session_id": env.get("session_id"),
                            "pending": env.get("pending_count"),
                            "ts": now(),
                        })),
                        Some("error") => {
                            let m = env
                                .get("message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            emit(json!({
                                "event": "error",
                                "message": m,
                                "code": env.get("error_code"),
                                "ts": now(),
                            }));
                            return Err(anyhow!("server error: {m}"));
                        }
                        _ => emit(json!({ "event": "envelope", "raw": s, "ts": now() })),
                    }
                } else {
                    emit(json!({ "event": "text", "raw": s, "ts": now() }));
                }
            }
            Message::Close(c) => {
                emit(json!({
                    "event": "closed",
                    "reason": c.map(|f| f.reason.to_string()),
                    "ts": now(),
                }));
                return Ok(());
            }
            Message::Ping(_) | Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
        }
    }
    emit(json!({ "event": "closed", "reason": null, "ts": now() }));
    Ok(())
}

/// Run the listener. With `reconnect`, retries with exponential backoff (1s → 30s cap)
/// and emits `{"event":"reconnecting", ...}` between attempts.
pub async fn run(id: &Identity, reconnect: bool) -> Result<()> {
    let key = id.project_key()?;
    let mut backoff = 1u64;
    loop {
        match session(id, &key).await {
            Ok(()) if !reconnect => return Ok(()),
            Ok(()) => {
                backoff = 1;
            }
            Err(e) if !reconnect => return Err(e),
            Err(e) => {
                emit(json!({
                    "event": "reconnecting",
                    "error": e.to_string(),
                    "in_secs": backoff,
                    "ts": now(),
                }));
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(30);
    }
}

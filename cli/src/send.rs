use crate::identity::Identity;
use crate::ws_session;
#[cfg(windows)]
use crate::pipe;
use anyhow::{Result, bail};
use serde::Deserialize;

/// Normalize a user-supplied identity string to `name@project` wire format.
/// Accepts `Name@Project` (v2) and `Name.Project` (v1, splits on last `.`).
fn normalize_identity(s: &str) -> String {
    if s.contains('@') {
        s.to_string()
    } else if let Some(dot) = s.rfind('.') {
        format!("{}@{}", &s[..dot], &s[dot + 1..])
    } else {
        s.to_string() // single token — broker will reject, but let it produce the error
    }
}

/// Build the C6 channel resource path `/channels/<chan>@<project>`.
/// Accepts: `#general`, `#general.Project`, `#general@Project`, `general`, `general@Project`.
/// When no cross-project qualifier is present, `sender_project` is used.
fn channel_path(channel: &str, sender_project: &str) -> String {
    let ch = channel.trim_start_matches('#');
    if ch.contains('@') {
        format!("/channels/{ch}")
    } else if let Some(dot) = ch.find('.') {
        format!("/channels/{}@{}", &ch[..dot], &ch[dot + 1..])
    } else {
        format!("/channels/{ch}@{sender_project}")
    }
}

/// Send a frame using the named pipe if `broker listen` is active (Windows),
/// otherwise fall back to a one-shot WS connection.
/// TODO: pipe auth token — currently no authentication on the pipe.
async fn send_frame(id: &Identity, frame: String) -> Result<()> {
    #[cfg(windows)]
    {
        let name = pipe::pipe_name(&id.project, &id.name);
        match pipe::try_send(&name, &frame).await {
            Some(Ok(resp)) => {
                if resp.starts_with("HTTP/1.1 2") {
                    return Ok(());
                }
                let status_line = resp.lines().next().unwrap_or("unknown error").to_string();
                bail!("pipe error: {status_line}");
            }
            Some(Err(e)) => bail!("pipe send failed: {e}"),
            None => {} // pipe not available (listen not running) → fall through to WS
        }
    }
    ws_session::send_one(id, frame).await
}

/// Send a direct message: `POST /v1/dms` with `from:` and `to:` headers.
pub async fn dm(id: &Identity, to: &str, body: &str) -> Result<()> {
    let from = id.fq();
    let to_canon = normalize_identity(to);
    let frame = format!("POST /v1/dms\r\nfrom: {from}\r\nto: {to_canon}\r\n\r\n{body}");
    send_frame(id, frame).await
}

/// Post to a channel: `POST /channels/<chan>@<project>` with `from:` and optional `mentions:`.
pub async fn post(
    id: &Identity,
    channel: &str,
    body: &str,
    mentions: Option<&str>,
) -> Result<()> {
    let from = id.fq();
    let path = channel_path(channel, &id.project);
    let mentions_line = mentions
        .map(|m| format!("mentions: {m}\r\n"))
        .unwrap_or_default();
    let frame = format!("POST {path}\r\nfrom: {from}\r\n{mentions_line}\r\n{body}");
    send_frame(id, frame).await
}

/// Update presence via `PUT /presence` with a JSON body `{"state": "..."}`.
/// Uses AgentAuth headers (X-Project, X-Project-Key, X-Agent-Name).
pub async fn presence(client: &reqwest::Client, id: &Identity, status: &str) -> Result<()> {
    let key = id.project_key()?;
    let resp = client
        .put(format!("{}/presence", id.broker_url))
        .header("X-Project", &id.project)
        .header("X-Project-Key", &key)
        .header("X-Agent-Name", &id.name)
        .json(&serde_json::json!({ "state": status }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("presence update failed: {}", body.trim());
    }
    Ok(())
}

/// Send a raw HttpFrame string verbatim. Caller is responsible for correct frame format.
pub async fn frame_raw(id: &Identity, raw: String) -> Result<()> {
    send_frame(id, raw).await
}

#[derive(Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub project: String,
    pub state: String,
    #[serde(default)]
    pub description: String,
}

pub async fn agents(
    client: &reqwest::Client,
    broker_url: &str,
    project: Option<&str>,
) -> Result<Vec<AgentInfo>> {
    let mut url = format!("{broker_url}/agents");
    if let Some(p) = project {
        url = format!("{url}?project={p}");
    }
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("agents query failed: {body}");
    }
    Ok(resp.json().await?)
}

#[derive(Deserialize)]
pub struct PendingMsg {
    pub from_agent: String,
    pub from_project: String,
    pub body: String,
    pub created_utc: String,
}

pub async fn messages(client: &reqwest::Client, id: &Identity) -> Result<Vec<PendingMsg>> {
    let key = id.project_key()?;
    let resp = client
        .get(format!("{}/messages", id.broker_url))
        .header("X-Project", &id.project)
        .header("X-Project-Key", &key)
        .header("X-Agent-Name", &id.name)
        .send()
        .await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("messages fetch failed: {body}");
    }
    Ok(resp.json().await?)
}

/// Long-poll /messages until at least one arrives or timeout elapses.
pub async fn await_messages(
    client: &reqwest::Client,
    id: &Identity,
    timeout_secs: u64,
    interval_secs: u64,
) -> Result<Vec<PendingMsg>> {
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
    loop {
        let msgs = messages(client, id).await?;
        if !msgs.is_empty() {
            return Ok(msgs);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(Vec::new());
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs.max(1))).await;
    }
}

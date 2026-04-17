use crate::identity::Identity;
use anyhow::{Result, bail};
use serde::Deserialize;

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Deserialize)]
struct SendResp {
    message_id: String,
}

async fn send_raw(client: &reqwest::Client, id: &Identity, stanza: String) -> Result<String> {
    let key = id.project_key()?;
    let resp = client
        .post(format!("{}/send", id.broker_url))
        .header("X-Project", &id.project)
        .header("X-Project-Key", &key)
        .header("X-Agent-Name", &id.name)
        .header("Content-Type", "application/xml")
        .body(stanza)
        .send()
        .await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("send failed: {body}");
    }
    let r: SendResp = resp.json().await?;
    Ok(r.message_id)
}

pub async fn dm(client: &reqwest::Client, id: &Identity, to: &str, body: &str) -> Result<String> {
    let stanza = format!(
        r#"<message type="dm" from="{}" to="{}"><body>{}</body></message>"#,
        id.name,
        to,
        xml_escape(body)
    );
    send_raw(client, id, stanza).await
}

pub async fn post(
    client: &reqwest::Client,
    id: &Identity,
    channel: &str,
    body: &str,
    mentions: Option<&str>,
) -> Result<String> {
    let chan = if channel.starts_with('#') {
        channel.to_string()
    } else {
        format!("#{channel}")
    };
    let mentions_attr = mentions
        .map(|m| format!(r#" mentions="{}""#, m))
        .unwrap_or_default();
    let stanza = format!(
        r#"<message type="post" from="{}" to="{}"{}> <body>{}</body></message>"#,
        id.name,
        chan,
        mentions_attr,
        xml_escape(body)
    );
    send_raw(client, id, stanza).await
}

pub async fn presence(client: &reqwest::Client, id: &Identity, status: &str) -> Result<String> {
    let stanza = format!(r#"<presence from="{}" status="{}"/>"#, id.name, status);
    send_raw(client, id, stanza).await
}

pub async fn stanza(client: &reqwest::Client, id: &Identity, raw: String) -> Result<String> {
    send_raw(client, id, raw).await
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

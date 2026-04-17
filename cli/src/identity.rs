use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_BROKER_URL: &str = "http://127.0.0.1:4200";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub project: String,
    pub broker_url: String,
}

impl Identity {
    pub fn fq(&self) -> String {
        format!("{}.{}", self.name, self.project)
    }

    /// Load the project key from ~/.agent-broker/keys/<project>.key (shared with the MCP server).
    pub fn project_key(&self) -> Result<String> {
        load_key(&self.project).ok_or_else(|| {
            anyhow!(
                "no project key for '{}'. Run `broker register --as {} ...` first, or place the key at {}",
                self.project,
                self.fq(),
                key_file_path(&self.project).display()
            )
        })
    }

    pub fn ws_url(&self) -> String {
        let base = if let Some(rest) = self.broker_url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.broker_url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            format!("ws://{}", self.broker_url)
        };
        format!("{}/ws", base.trim_end_matches('/'))
    }
}

fn base_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agent-broker")
}

fn key_file_path(project: &str) -> PathBuf {
    base_dir().join("keys").join(format!("{project}.key"))
}

fn load_key(project: &str) -> Option<String> {
    std::fs::read_to_string(key_file_path(project))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_key(project: &str, key: &str) {
    let path = key_file_path(project);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, key);
}

fn session_path() -> PathBuf {
    base_dir().join("cli-session.json")
}

fn save_session(id: &Identity) -> Result<()> {
    let path = session_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(id)?)?;
    Ok(())
}

fn load_session() -> Option<Identity> {
    let s = std::fs::read_to_string(session_path()).ok()?;
    serde_json::from_str(&s).ok()
}

/// Parse "Name.Project" — splits on the LAST '.' so names may contain dots.
pub fn parse_as(s: &str) -> Result<(String, String)> {
    let idx = s
        .rfind('.')
        .ok_or_else(|| anyhow!("--as must be Name.Project (e.g. Boss-25435.ClaudeCode)"))?;
    let (name, project) = (&s[..idx], &s[idx + 1..]);
    if name.is_empty() || project.is_empty() {
        bail!("--as must be Name.Project (got '{s}')");
    }
    Ok((name.to_string(), project.to_string()))
}

/// Resolve identity for a one-shot command: --as flag wins, else cli-session.json, else error.
/// `url` is the resolved broker URL (CLI flag → BROKER_URL env → default).
pub fn resolve(as_flag: Option<&str>, url: &str) -> Result<Identity> {
    if let Some(spec) = as_flag {
        let (name, project) = parse_as(spec)?;
        return Ok(Identity {
            name,
            project,
            broker_url: url.to_string(),
        });
    }
    let mut sess = load_session().ok_or_else(|| {
        anyhow!("no active CLI identity. Pass --as Name.Project or run `broker register` first.")
    })?;
    // CLI/env URL overrides the saved one only if it differs from default resolution.
    if url != DEFAULT_BROKER_URL || std::env::var("BROKER_URL").is_ok() {
        sess.broker_url = url.to_string();
    }
    Ok(sess)
}

pub fn resolve_url(flag: Option<&str>) -> String {
    flag.map(|s| s.to_string())
        .or_else(|| std::env::var("BROKER_URL").ok())
        .unwrap_or_else(|| DEFAULT_BROKER_URL.to_string())
}

#[derive(Deserialize)]
struct RegProjResp {
    project_key: String,
}

/// POST /projects/register → /agents/register, persist key + cli-session.json.
pub async fn register(
    client: &reqwest::Client,
    name: &str,
    project: &str,
    description: Option<&str>,
    broker_url: &str,
) -> Result<Identity> {
    // Project: register or load existing key on 409.
    let resp = client
        .post(format!("{broker_url}/projects/register"))
        .json(&serde_json::json!({ "name": project }))
        .send()
        .await
        .with_context(|| format!("broker unreachable at {broker_url}"))?;

    let project_key = if resp.status().is_success() {
        resp.json::<RegProjResp>().await?.project_key
    } else if resp.status().as_u16() == 409 {
        load_key(project).ok_or_else(|| {
            anyhow!(
                "project '{project}' already exists but no key at {}. \
                 Place the key there or use a different project.",
                key_file_path(project).display()
            )
        })?
    } else {
        let body = resp.text().await.unwrap_or_default();
        bail!("project registration failed: {body}");
    };

    // Agent.
    let resp = client
        .post(format!("{broker_url}/agents/register"))
        .json(&serde_json::json!({
            "name": name,
            "project": project,
            "project_key": project_key,
            "role": "assistant",
            "description": description.unwrap_or(""),
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("agent registration failed: {body}");
    }

    save_key(project, &project_key);
    let id = Identity {
        name: name.to_string(),
        project: project.to_string(),
        broker_url: broker_url.to_string(),
    };
    save_session(&id)?;
    Ok(id)
}

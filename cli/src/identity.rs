use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
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
    /// Fully-qualified identity in `name@project` wire format.
    pub fn fq(&self) -> String {
        format!("{}@{}", self.name, self.project)
    }

    /// Load the project key from ~/.agent-broker/keys/<project>.key (shared with the MCP server).
    pub fn project_key(&self) -> Result<String> {
        load_key(&self.project).ok_or_else(|| {
            let path_hint = key_file_path(&self.project)
                .map(|p| format!(" or place the key at {}", p.display()))
                .unwrap_or_default();
            anyhow!(
                "no project key for '{}'. Run `broker register --as {}@{}` first{}.",
                self.project,
                self.name,
                self.project,
                path_hint,
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

fn key_file_path(project: &str) -> Result<PathBuf> {
    validate_path_segment(project, "project")?;
    Ok(base_dir().join("keys").join(format!("{project}.key")))
}

/// Reject any path segment containing `/`, `\`, or null bytes.
/// This prevents directory traversal when building key storage paths from
/// user-supplied `name` and `project` strings.
fn validate_path_segment(s: &str, label: &str) -> Result<()> {
    if s.is_empty() {
        bail!("{label} must not be empty");
    }
    if s.bytes().any(|b| b == b'/' || b == b'\\' || b == b'\0') {
        bail!("{label} '{s}' contains path-unsafe characters (/, \\, or null)");
    }
    Ok(())
}

fn ed25519_key_path(project: &str, name: &str) -> Result<PathBuf> {
    validate_path_segment(project, "project")?;
    validate_path_segment(name, "name")?;
    Ok(base_dir().join("keys").join(format!("{project}-{name}.ed25519")))
}

fn load_key(project: &str) -> Option<String> {
    let path = key_file_path(project).ok()?;
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn save_key(project: &str, key: &str) -> Result<()> {
    let path = key_file_path(project)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create key directory {}", parent.display()))?;
    }
    std::fs::write(&path, key)
        .with_context(|| format!("write project key to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set 0o600 permissions on {}", path.display()))?;
    }
    Ok(())
}

/// Write the Ed25519 signing key to disk and set permissions to 0o600 (owner r/w only).
/// Returns an error if the path segments are unsafe, the directory cannot be created,
/// the write fails, or (on Unix) the permission change fails.
fn save_ed25519_key(project: &str, name: &str, signing_key: &SigningKey) -> Result<()> {
    let path = ed25519_key_path(project, name)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create key directory {}", parent.display()))?;
    }
    std::fs::write(&path, hex::encode(signing_key.to_bytes()))
        .with_context(|| format!("write Ed25519 key to {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set 0o600 permissions on {}", path.display()))?;
    }
    Ok(())
}

/// Load the Ed25519 signing key for `name@project` from disk.
/// Returns `None` if the segments are unsafe, the file is missing, or the contents are invalid.
pub fn load_ed25519_key(project: &str, name: &str) -> Option<SigningKey> {
    let path = ed25519_key_path(project, name).ok()?;
    let hex_str = std::fs::read_to_string(path).ok()?;
    let bytes: [u8; 32] = hex::decode(hex_str.trim()).ok()?.try_into().ok()?;
    Some(SigningKey::from_bytes(&bytes))
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

/// Parse `Name@Project` or `Name.Project` (splits on last `.` when no `@` present).
pub fn parse_as(s: &str) -> Result<(String, String)> {
    // Prefer `@` separator (v2 format).
    if let Some(at) = s.find('@') {
        let name = &s[..at];
        let project = &s[at + 1..];
        if !name.is_empty() && !project.is_empty() {
            return Ok((name.to_string(), project.to_string()));
        }
    }
    // Fall back to last `.` (v1 format, project names may contain dots).
    let idx = s
        .rfind('.')
        .ok_or_else(|| anyhow!("identity must be Name@Project or Name.Project (e.g. Boss@ClaudeCode)"))?;
    let (name, project) = (&s[..idx], &s[idx + 1..]);
    if name.is_empty() || project.is_empty() {
        bail!("identity must be Name@Project or Name.Project (got '{s}')");
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
        anyhow!("no active CLI identity. Pass --as Name@Project or run `broker register` first.")
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

/// POST /projects/register → /agents/register, persist keys + cli-session.json.
/// Generates an Ed25519 keypair and enrolls the public key at registration time.
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
            let path_hint = key_file_path(project)
                .map(|p| format!(" at {}", p.display()))
                .unwrap_or_default();
            anyhow!(
                "project '{project}' already exists but no key found{}. \
                 Place the key there or use a different project.",
                path_hint,
            )
        })?
    } else {
        let body = resp.text().await.unwrap_or_default();
        bail!("project registration failed: {body}");
    };

    // Generate Ed25519 keypair for WS challenge-response auth.
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    // Agent: register with Ed25519 public key enrolled.
    let resp = client
        .post(format!("{broker_url}/agents/register"))
        .json(&serde_json::json!({
            "name": name,
            "project": project,
            "project_key": project_key,
            "role": "assistant",
            "description": description.unwrap_or(""),
            "public_key": pubkey_hex,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("agent registration failed: {body}");
    }

    save_key(project, &project_key)?;
    save_ed25519_key(project, name, &signing_key)?;

    let id = Identity {
        name: name.to_string(),
        project: project.to_string(),
        broker_url: broker_url.to_string(),
    };
    save_session(&id)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── key_file_path ─────────────────────────────────────────────────────────

    #[test]
    fn key_file_path_clean_inputs_succeed() {
        let p = key_file_path("MyProject").unwrap();
        assert!(p.to_string_lossy().ends_with("MyProject.key"));
    }

    #[test]
    fn key_file_path_slash_in_project_errors() {
        assert!(key_file_path("bad/project").is_err());
        assert!(key_file_path("../../etc").is_err());
    }

    #[test]
    fn key_file_path_backslash_in_project_errors() {
        assert!(key_file_path("bad\\project").is_err());
    }

    // ── validate_path_segment ─────────────────────────────────────────────────

    #[test]
    fn valid_segment_accepted() {
        assert!(validate_path_segment("MyProject", "project").is_ok());
        assert!(validate_path_segment("AITeam.Platform", "project").is_ok());
        assert!(validate_path_segment("agent-name_42", "name").is_ok());
    }

    #[test]
    fn empty_segment_rejected() {
        assert!(validate_path_segment("", "project").is_err());
    }

    #[test]
    fn forward_slash_rejected() {
        assert!(validate_path_segment("proj/evil", "project").is_err());
        assert!(validate_path_segment("../../etc/passwd", "name").is_err());
    }

    #[test]
    fn backslash_rejected() {
        assert!(validate_path_segment("proj\\evil", "project").is_err());
    }

    #[test]
    fn null_byte_rejected() {
        assert!(validate_path_segment("proj\0evil", "project").is_err());
    }

    // ── ed25519_key_path ──────────────────────────────────────────────────────

    #[test]
    fn key_path_clean_inputs_succeed() {
        let p = ed25519_key_path("MyProj", "Alice").unwrap();
        assert!(p.to_string_lossy().ends_with("MyProj-Alice.ed25519"));
    }

    #[test]
    fn key_path_slash_in_project_errors() {
        assert!(ed25519_key_path("bad/proj", "Alice").is_err());
    }

    #[test]
    fn key_path_slash_in_name_errors() {
        assert!(ed25519_key_path("MyProj", "../evil").is_err());
    }
}

use crate::session::{SessionManager, load_key, lookup_identity};
use rmcp::{
    ServerHandler,
    handler::server::{
        router::tool::ToolRouter,
        wrapper::Parameters,
    },
    model::*,
    schemars, tool, tool_router, tool_handler,
};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;

const DEFAULT_BROKER_URL: &str = "http://127.0.0.1:4200";

#[derive(Clone)]
pub struct BrokerTools {
    client: Client,
    session: Arc<SessionManager>,
    tool_router: ToolRouter<BrokerTools>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RegisterArgs {
    /// Your agent name (e.g. "Archie"). Optional if previously registered from this directory.
    #[serde(default)]
    pub name: Option<String>,
    /// Project name (e.g. "CopilotCLI")
    pub project: String,
    /// Broker URL override. Defaults to http://127.0.0.1:4200
    #[serde(default)]
    pub broker_url: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    /// Target agent -- fully qualified for cross-project: "Name.Project"
    pub to: String,
    /// Message body text
    pub message: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PresenceArgs {
    /// Optional project name to filter by
    #[serde(default)]
    pub project: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct StanzaArgs {
    /// Raw stanza XML to send
    pub stanza: String,
}

#[derive(Deserialize)]
struct RegProjResp { project_key: String }
#[derive(Deserialize)]
struct SendResp { message_id: String }
#[derive(Deserialize)]
struct AgentInfo { name: String, project: String, state: String }
#[derive(Deserialize)]
struct PendingMsg { from_agent: String, from_project: String, body: String, created_utc: String }
#[derive(Deserialize)]
struct PeekSender { from: String, at: String }
#[derive(Deserialize)]
struct PeekResp { count: usize, senders: Vec<PeekSender> }

fn mcp_err(msg: String) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(msg, None)
}

/// Escape XML special characters in plain-text content before embedding in a stanza.
/// Applied only to user-supplied plain text (broker_send message param), not to raw XML.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}

#[tool_router]
impl BrokerTools {
    pub fn new() -> Self {
        Self {
            client: Client::builder().timeout(std::time::Duration::from_secs(5)).build().unwrap(),
            session: Arc::new(SessionManager::new()),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Register with the agent-broker. Must be called before other tools.")]
    async fn broker_register(&self, Parameters(args): Parameters<RegisterArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        let agent_name = match args.name {
            Some(n) => n,
            None => lookup_identity().ok_or_else(|| rmcp::ErrorData::invalid_params(
                "No agent name provided and no saved identity for this directory. Pass 'name' on first use.", None))?,
        };

        let broker_url = args.broker_url
            .unwrap_or_else(|| std::env::var("BROKER_URL").unwrap_or_else(|_| DEFAULT_BROKER_URL.to_string()));

        let proj_resp = self.client.post(format!("{}/projects/register", broker_url))
            .json(&serde_json::json!({ "name": args.project }))
            .send().await.map_err(|e| mcp_err(format!("Broker unreachable: {e}")))?;

        let project_key = if proj_resp.status().is_success() {
            proj_resp.json::<RegProjResp>().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?.project_key
        } else if proj_resp.status().as_u16() == 409 {
            // Project exists -- load key from file
            load_key(&args.project).ok_or_else(|| rmcp::ErrorData::invalid_params(
                format!("Project '{}' exists but no saved key found. If you own this project, place the key in ~/.agent-broker/keys/{}.key",
                         args.project, args.project), None))?
        } else {
            let body = proj_resp.text().await.unwrap_or_default();
            return Err(mcp_err(format!("Project registration failed: {body}")));
        };

        let resp = self.client.post(format!("{}/agents/register", broker_url))
            .json(&serde_json::json!({
                "name": agent_name, "project": args.project,
                "project_key": project_key, "role": "assistant"
            }))
            .send().await.map_err(|e| mcp_err(format!("Agent reg failed: {e}")))?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(mcp_err(format!("Agent registration failed: {body}")));
        }

        // Delegate key persistence, identity persistence, and session mutation to SessionManager
        self.session.register(agent_name.clone(), args.project.clone(), project_key, broker_url.clone());

        Ok(CallToolResult::success(vec![Content::text(
            format!("Registered as {}.{} on {}", agent_name, args.project, broker_url))]))
    }

    #[tool(description = "List online agents. Optionally filter by project.")]
    async fn broker_presence(&self, Parameters(args): Parameters<PresenceArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_, _, _, url) = self.session.get()?;
        let mut ep = format!("{}/agents", url);
        if let Some(ref p) = args.project { ep = format!("{}?project={}", ep, p); }

        let agents: Vec<AgentInfo> = self.client.get(&ep).send().await
            .map_err(|e| mcp_err(format!("Broker unreachable: {e}")))?
            .json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;

        if agents.is_empty() { return Ok(CallToolResult::success(vec![Content::text("No agents online.")])); }
        let lines: Vec<String> = agents.iter().map(|a| format!("{}.{} -- {}", a.name, a.project, a.state)).collect();
        Ok(CallToolResult::success(vec![Content::text(lines.join("\n"))]))
    }

    #[tool(description = "Send a DM to an agent. Use 'Name.Project' for cross-project. For channels/threads/reactions use broker_send_stanza.")]
    async fn broker_send(&self, Parameters(args): Parameters<SendArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        // T7: reject empty or whitespace-only messages before constructing the stanza
        if args.message.trim().is_empty() {
            return Err(mcp_err("message must not be empty".to_string()));
        }
        let (name, ..) = self.session.get()?;
        // T3: XML-escape plain text to produce a well-formed stanza body
        let stanza = format!("<message type=\"dm\" from=\"{}\" to=\"{}\">{}</message>", name, args.to, xml_escape(&args.message));
        self.send_raw(stanza).await
    }

    async fn send_raw(&self, stanza: String) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_, project, key, url) = self.session.get()?;
        let resp = self.client.post(format!("{}/send", url))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .header("Content-Type", "application/xml")
            .body(stanza)
            .send().await.map_err(|e| mcp_err(format!("Send failed: {e}")))?;
        if resp.status().is_success() {
            let r: SendResp = resp.json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;
            Ok(CallToolResult::success(vec![Content::text(format!("Sent (id: {})", r.message_id))]))
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(mcp_err(format!("Send failed: {body}")))
        }
    }

    #[tool(description = "Send a raw stanza XML frame. Use for channel posts, replies, reactions, and presence updates.")]
    async fn broker_send_stanza(&self, Parameters(args): Parameters<StanzaArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        self.send_raw(args.stanza).await
    }

    #[tool(description = "Peek at pending messages: count and senders, without consuming.")]
    async fn broker_peek(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let (name, project, key, url) = self.session.get()?;
        let peek: PeekResp = self.client
            .get(format!("{}/messages/peek?name={}", url, name))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .send().await.map_err(|e| mcp_err(format!("Peek failed: {e}")))?
            .json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;

        if peek.count == 0 { return Ok(CallToolResult::success(vec![Content::text("No pending messages.")])); }
        let lines: Vec<String> = peek.senders.iter().map(|s| format!("  from {} at {}", s.from, s.at)).collect();
        Ok(CallToolResult::success(vec![Content::text(format!("{} pending message(s):\n{}", peek.count, lines.join("\n")))]))
    }

    #[tool(description = "Retrieve and consume all pending messages.")]
    async fn broker_messages(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let (name, project, key, url) = self.session.get()?;
        let messages: Vec<PendingMsg> = self.client
            .get(format!("{}/messages?name={}", url, name))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .send().await.map_err(|e| mcp_err(format!("Fetch failed: {e}")))?
            .json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;

        if messages.is_empty() { return Ok(CallToolResult::success(vec![Content::text("No pending messages.")])); }
        let lines: Vec<String> = messages.iter()
            .map(|m| format!("--- from {}.{} at {} ---\n{}", m.from_agent, m.from_project, m.created_utc, m.body))
            .collect();
        Ok(CallToolResult::success(vec![Content::text(format!("{} message(s):\n\n{}", messages.len(), lines.join("\n\n")))]))
    }
}

#[tool_handler]
impl ServerHandler for BrokerTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_instructions("Agent broker MCP. Call broker_register first, then broker_presence, broker_send, broker_send_stanza, broker_peek, broker_messages.".to_string())
    }
}

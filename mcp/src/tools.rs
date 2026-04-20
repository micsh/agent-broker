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
    /// Optional description of what this agent does. Shown in agent listings.
    #[serde(default)]
    pub description: Option<String>,
    /// Broker URL override. Defaults to http://127.0.0.1:4200
    #[serde(default)]
    pub broker_url: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    /// Target agent in 'name@project' format (e.g. "Bob@myproject"). Same project: just 'Bob@myproject'.
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
pub struct FramePostArgs {
    /// Channel address in '#channel.project' format (e.g. '#general.myproject')
    pub channel: String,
    /// Message body text
    pub body: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ToolRegisterArgs {
    /// Tool name (globally unique, max 128 chars, no leading/trailing whitespace)
    pub name: String,
    /// Prose description of what the tool does and when to use it (required, max 2000 chars)
    pub description: String,
    /// Freeform responsible party text (e.g. "Operator project CopilotCli"). Optional.
    #[serde(default)]
    pub maintainer: Option<String>,
    /// Routing hint — DM target, channel address, or URL. Optional.
    #[serde(default)]
    pub contact: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ToolNameArgs {
    /// Tool name to look up or deregister
    pub name: String,
}

#[derive(Deserialize)]
struct RegProjResp { project_key: String }
#[derive(Deserialize)]
struct AgentInfo { name: String, project: String, state: String, #[serde(default)] description: String }
#[derive(Deserialize)]
struct PendingMsg { from_agent: String, from_project: String, body: String, created_utc: String }
#[derive(Deserialize)]
struct PeekSender { from: String, at: String }
#[derive(Deserialize)]
struct PeekResp { count: usize, senders: Vec<PeekSender> }
#[derive(Deserialize)]
struct McpToolEntry {
    name: String,
    description: String,
    maintainer: String,
    contact: String,
    registered_by: String,
    last_updated: String,
}

fn mcp_err(msg: String) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(msg, None)
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
                "project_key": project_key, "role": "assistant",
                "description": args.description.unwrap_or_default()
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
        let lines: Vec<String> = agents.iter().map(|a| {
            let desc = if a.description.is_empty() { String::new() } else { format!(" — {}", a.description) };
            format!("{}.{} -- {}{}", a.name, a.project, a.state, desc)
        }).collect();
        Ok(CallToolResult::success(vec![Content::text(lines.join("\n"))]))
    }

    #[tool(description = "Send a DM to an agent. Use 'name@project' format (e.g. 'Bob@myproject').")]
    async fn broker_send(&self, Parameters(args): Parameters<SendArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        // Reject empty or whitespace-only messages before constructing the frame
        if args.message.trim().is_empty() {
            return Err(mcp_err("message must not be empty".to_string()));
        }
        let (name, project, ..) = self.session.get()?;
        let frame_text = format!(
            "POST /v1/dms HTTP/1.1\r\nX-From: {}@{}\r\nX-To: {}\r\nContent-Length: {}\r\n\r\n{}",
            name, project, args.to, args.message.len(), args.message
        );
        self.send_raw(frame_text).await
    }

    async fn send_raw(&self, frame_text: String) -> Result<CallToolResult, rmcp::ErrorData> {
        let (name, project, key, url) = self.session.get()?;
        let resp = self.client.post(format!("{}/v1/send", url))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .header("X-Agent-Name", &name)
            .header("Content-Type", "text/plain")
            .body(frame_text)
            .send().await.map_err(|e| mcp_err(format!("Send failed: {e}")))?;
        if resp.status().is_success() {
            Ok(CallToolResult::success(vec![Content::text("Sent.")]))
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(mcp_err(format!("Send failed: {body}")))
        }
    }

    #[tool(description = "Post a message to a channel. Channel must be in '#channel.project' format.")]
    async fn broker_frame_post(&self, Parameters(args): Parameters<FramePostArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        if args.body.trim().is_empty() {
            return Err(mcp_err("body must not be empty".to_string()));
        }
        let (name, project, ..) = self.session.get()?;
        let frame_text = format!(
            "POST /v1/posts HTTP/1.1\r\nX-From: {}@{}\r\nX-To: {}\r\nContent-Length: {}\r\n\r\n{}",
            name, project, args.channel, args.body.len(), args.body
        );
        self.send_raw(frame_text).await
    }

    #[tool(description = "Peek at pending messages: count and senders, without consuming.")]
    async fn broker_peek(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let (name, project, key, url) = self.session.get()?;
        let peek: PeekResp = self.client
            .get(format!("{}/messages/peek", url))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .header("X-Agent-Name", &name)
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
            .get(format!("{}/messages", url))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .header("X-Agent-Name", &name)
            .send().await.map_err(|e| mcp_err(format!("Fetch failed: {e}")))?
            .json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;

        if messages.is_empty() { return Ok(CallToolResult::success(vec![Content::text("No pending messages.")])); }
        let lines: Vec<String> = messages.iter()
            .map(|m| format!("--- from {}.{} at {} ---\n{}", m.from_agent, m.from_project, m.created_utc, m.body))
            .collect();
        Ok(CallToolResult::success(vec![Content::text(format!("{} message(s):\n\n{}", messages.len(), lines.join("\n\n")))]))
    }

    #[tool(description = "Register or update a tool entry in the broker registry. Any agent can claim any name (last write wins). Requires active session.")]
    async fn broker_tool_register(&self, Parameters(args): Parameters<ToolRegisterArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        let (agent_name, project, key, url) = self.session.get()?;
        let resp = self.client
            .put(format!("{}/tools/{}", url, args.name))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .header("X-Agent-Name", &agent_name)
            .json(&serde_json::json!({
                "description": args.description,
                "maintainer": args.maintainer,
                "contact": args.contact,
            }))
            .send().await.map_err(|e| mcp_err(format!("Broker unreachable: {e}")))?;
        if resp.status().is_success() {
            let entry: McpToolEntry = resp.json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;
            Ok(CallToolResult::success(vec![Content::text(
                format!("Registered tool '{}' (last updated {})", entry.name, entry.last_updated))]))
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(mcp_err(format!("Tool registration failed: {body}")))
        }
    }

    #[tool(description = "Look up a tool by name. Returns its description, maintainer, and contact info. Returns null-equivalent text if not registered.")]
    async fn broker_tool_get(&self, Parameters(args): Parameters<ToolNameArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_, _, _, url) = self.session.get()?;
        let resp = self.client
            .get(format!("{}/tools/{}", url, args.name))
            .send().await.map_err(|e| mcp_err(format!("Broker unreachable: {e}")))?;
        if resp.status().as_u16() == 404 {
            return Ok(CallToolResult::success(vec![Content::text(format!("Tool '{}' is not registered.", args.name))]));
        }
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(mcp_err(format!("Tool lookup failed: {body}")));
        }
        let entry: McpToolEntry = resp.json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;
        let maintainer = if entry.maintainer.is_empty() { "unspecified".to_string() } else { entry.maintainer };
        let contact = if entry.contact.is_empty() { "unspecified".to_string() } else { entry.contact };
        Ok(CallToolResult::success(vec![Content::text(format!(
            "{} — {}\n  maintainer: {}\n  contact: {}\n  registered_by: {}\n  last_updated: {}",
            entry.name, entry.description, maintainer, contact, entry.registered_by, entry.last_updated
        ))]))
    }

    #[tool(description = "Browse all registered tools. Useful for discovering available capabilities and their maintainers.")]
    async fn broker_tool_list(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let (_, _, _, url) = self.session.get()?;
        let tools: Vec<McpToolEntry> = self.client
            .get(format!("{}/tools", url))
            .send().await.map_err(|e| mcp_err(format!("Broker unreachable: {e}")))?
            .json().await.map_err(|e| mcp_err(format!("Bad response: {e}")))?;
        if tools.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text("No tools registered.")]));
        }
        let lines: Vec<String> = tools.iter().map(|t| {
            let maintainer = if t.maintainer.is_empty() { "unspecified".to_string() } else { t.maintainer.clone() };
            format!("{} — {}\n  maintainer: {}\n  registered_by: {}", t.name, t.description, maintainer, t.registered_by)
        }).collect();
        Ok(CallToolResult::success(vec![Content::text(lines.join("\n\n"))]))
    }

    #[tool(description = "Deregister a tool entry. Use when a tool is decommissioned. Requires active session.")]
    async fn broker_tool_deregister(&self, Parameters(args): Parameters<ToolNameArgs>) -> Result<CallToolResult, rmcp::ErrorData> {
        let (agent_name, project, key, url) = self.session.get()?;
        let resp = self.client
            .delete(format!("{}/tools/{}", url, args.name))
            .header("X-Project", &project)
            .header("X-Project-Key", &key)
            .header("X-Agent-Name", &agent_name)
            .send().await.map_err(|e| mcp_err(format!("Broker unreachable: {e}")))?;
        match resp.status().as_u16() {
            204 => Ok(CallToolResult::success(vec![Content::text(format!("Tool '{}' deregistered.", args.name))])),
            404 => Ok(CallToolResult::success(vec![Content::text(format!("Tool '{}' is not registered.", args.name))])),
            _ => {
                let body = resp.text().await.unwrap_or_default();
                Err(mcp_err(format!("Deregister failed: {body}")))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for BrokerTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_instructions("Agent broker MCP. Call broker_register first, then broker_presence, broker_send (DMs), broker_frame_post (channel posts), broker_peek, broker_messages. Tool registry: broker_tool_register, broker_tool_list, broker_tool_get, broker_tool_deregister.".to_string())
    }
}

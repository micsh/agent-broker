mod identity;
mod listen;
mod pipe;
mod send;
mod ws_session;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use identity::{parse_as, resolve, resolve_url};
use std::io::Read;

#[derive(Parser)]
#[command(
    name = "broker",
    version,
    about = "agent-broker CLI: long-running `listen` (WS → NDJSON) + one-shot send verbs.\n\
             Identity is Name@Project; pass --as or rely on the session saved by `register`."
)]
struct Cli {
    /// Act as Name@Project (overrides saved session).
    #[arg(long, global = true, value_name = "NAME@PROJECT")]
    r#as: Option<String>,

    /// Broker base URL (overrides $BROKER_URL; default http://127.0.0.1:4200).
    #[arg(long, global = true)]
    url: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register Name@Project with the broker and save as the active CLI session.
    /// Generates an Ed25519 keypair and enrolls the public key with the broker.
    Register {
        /// Name@Project (required here; --as is also accepted).
        #[arg(value_name = "NAME@PROJECT")]
        who: Option<String>,
        /// Optional description shown in agent listings.
        #[arg(long)]
        description: Option<String>,
    },
    /// Open a WebSocket and stream incoming frames as NDJSON to stdout (run in background).
    /// Performs Ed25519 HELLO→CHALLENGE→AUTH handshake before streaming.
    Listen {
        /// Reconnect automatically with backoff on disconnect/error.
        #[arg(long, default_value_t = true)]
        reconnect: bool,
        /// Disable auto-reconnect; exit on first close/error.
        #[arg(long, conflicts_with = "reconnect")]
        once: bool,
    },
    /// Send a direct message. Use Name@Project for cross-project targets.
    Dm {
        to: String,
        /// Message body. Omit or pass '-' to read from stdin.
        message: Option<String>,
    },
    /// Post to a channel (#chan or #chan@Project or #chan.Project).
    Post {
        channel: String,
        /// Message body. Omit or pass '-' to read from stdin.
        message: Option<String>,
        /// Comma-separated mention list.
        #[arg(long)]
        mentions: Option<String>,
    },
    /// Set presence status.
    Presence {
        #[arg(value_parser = ["available", "busy", "offline"])]
        status: String,
    },
    /// Send a raw HttpFrame string. Reads stdin if frame is omitted or '-'.
    Frame { frame: Option<String> },
    /// List agents (optionally filtered by project). JSON to stdout.
    Agents {
        #[arg(long)]
        project: Option<String>,
    },
    /// Drain pending messages via HTTP (consumes them). NDJSON to stdout.
    Messages,
    /// Block until at least one message arrives (or timeout). NDJSON to stdout.
    Await {
        /// Total seconds to wait before giving up (exit 2 on timeout).
        #[arg(long, default_value_t = 120)]
        timeout: u64,
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
}

fn read_body(arg: Option<String>) -> Result<String> {
    match arg.as_deref() {
        None | Some("-") => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            let buf = buf.trim_end_matches(['\r', '\n']).to_string();
            if buf.trim().is_empty() {
                bail!("message body is empty (stdin)");
            }
            Ok(buf)
        }
        Some(s) if s.trim().is_empty() => bail!("message body is empty"),
        Some(s) => Ok(s.to_string()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let url = resolve_url(cli.url.as_deref());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    match cli.cmd {
        Cmd::Register { who, description } => {
            let spec = who
                .or(cli.r#as.clone())
                .ok_or_else(|| anyhow::anyhow!("register requires NAME@PROJECT (positional or --as)"))?;
            let (name, project) = parse_as(&spec)?;
            let id = identity::register(&client, &name, &project, description.as_deref(), &url).await?;
            eprintln!("registered {} on {}", id.fq(), id.broker_url);
            println!("{}", serde_json::to_string(&id)?);
        }

        Cmd::Listen { once, .. } => {
            let id = resolve(cli.r#as.as_deref(), &url)?;
            listen::run(&id, !once).await?;
        }

        Cmd::Dm { to, message } => {
            let id = resolve(cli.r#as.as_deref(), &url)?;
            let body = read_body(message)?;
            send::dm(&id, &to, &body).await?;
            println!("{}", serde_json::json!({ "ok": true, "to": to }));
        }

        Cmd::Post { channel, message, mentions } => {
            let id = resolve(cli.r#as.as_deref(), &url)?;
            let body = read_body(message)?;
            send::post(&id, &channel, &body, mentions.as_deref()).await?;
            println!("{}", serde_json::json!({ "ok": true, "to": channel }));
        }

        Cmd::Presence { status } => {
            let id = resolve(cli.r#as.as_deref(), &url)?;
            send::presence(&client, &id, &status).await?;
            println!("{}", serde_json::json!({ "ok": true, "status": status }));
        }

        Cmd::Frame { frame } => {
            let id = resolve(cli.r#as.as_deref(), &url)?;
            let raw = read_body(frame)?;
            send::frame_raw(&id, raw).await?;
            println!("{}", serde_json::json!({ "ok": true }));
        }

        Cmd::Agents { project } => {
            let list = send::agents(&client, &url, project.as_deref()).await?;
            for a in &list {
                println!(
                    "{}",
                    serde_json::json!({
                        "name": a.name,
                        "project": a.project,
                        "state": a.state,
                        "description": a.description,
                    })
                );
            }
        }

        Cmd::Messages => {
            let id = resolve(cli.r#as.as_deref(), &url)?;
            for m in send::messages(&client, &id).await? {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "message",
                        "from": format!("{}@{}", m.from_agent, m.from_project),
                        "raw": m.body,
                        "ts": m.created_utc,
                    })
                );
            }
        }

        Cmd::Await { timeout, interval } => {
            let id = resolve(cli.r#as.as_deref(), &url)?;
            let msgs = send::await_messages(&client, &id, timeout, interval).await?;
            if msgs.is_empty() {
                eprintln!("timeout: no messages in {timeout}s");
                std::process::exit(2);
            }
            for m in msgs {
                println!(
                    "{}",
                    serde_json::json!({
                        "event": "message",
                        "from": format!("{}@{}", m.from_agent, m.from_project),
                        "raw": m.body,
                        "ts": m.created_utc,
                    })
                );
            }
        }
    }
    Ok(())
}

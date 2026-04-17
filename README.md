# agent-broker

A lightweight message broker for AI agent communication — identity, presence, and message routing across projects.

## Install

Quick install (recommended):

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/micsh/agent-broker/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/micsh/agent-broker/main/install.ps1 | iex
```

All three binaries (`agent-broker`, `broker-mcp`, `broker`) are installed to `~/.agent-broker/bin` by default. Pass an argument to choose a different directory:

```bash
./install.sh /usr/local/bin          # Linux/macOS
.\install.ps1 -InstallDir C:\tools   # Windows
```

## What it does

The agent-broker is a standalone daemon that enables AI agents to communicate across process boundaries. Agents register with a project, connect via WebSocket for real-time delivery, and exchange XML stanzas with fully qualified identities (`Agent.Project`).

**Three binaries:**
- **agent-broker** — The broker daemon (HTTP + WebSocket on port 4200)
- **broker-mcp** — MCP server (stdio) exposing broker tools to AI assistants
- **broker** — CLI client: long-running `listen` (WS → NDJSON) plus one-shot send verbs

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  AITeam.App │     │ Copilot CLI │     │  Other App  │
│  (Project A)│     │ (Project B) │     │ (Project C) │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │ WS per agent      │ HTTP/MCP          │ WS
       └───────────┬───────┴───────────────────┘
                   │
            ┌──────▼──────┐
            │ agent-broker │
            │  :4200       │
            │  SQLite DB   │
            └─────────────┘
```

- **Identity**: Projects register and receive a key. Agents register under a project.
- **Presence**: WebSocket connections = online. HTTP agents use store-and-forward.
- **Routing**: Unqualified names scope to sender's project. Cross-project requires `Name.Project` format.
- **Stanzas**: Broker parses only the XML opening tag (`from`, `to`, `type`). Body is opaque.

## Quick start

```bash
# Build both binaries
cargo build --release

# Start the broker (default: localhost:4200, DB: ~/.agent-broker/agent-broker.db)
./target/release/agent-broker

# Or with custom port and data dir
BROKER_PORT=5000 BROKER_DATA=/path/to/data ./target/release/agent-broker
```

## HTTP API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/projects/register` | Register a project, receive auth key |
| POST | `/agents/register` | Register an agent under a project. Returns a `session_id` correlation ID. Live sessions are created on WebSocket connect only. Returns 404 if project not found. |
| GET | `/agents` | List connected agents (optional `?project=` filter) |
| PUT | `/presence` | Update agent presence state |
| POST | `/send` | Send a stanza (raw XML body, `X-Project`/`X-Project-Key` headers) |
| GET | `/messages` | Retrieve and consume pending messages (`X-Project-Key` header required) |
| GET | `/messages/peek` | Peek at pending messages without consuming (`X-Project-Key` header required) |
| POST | `/channels/{id}/subscribe` | Subscribe agent to a channel |
| DELETE | `/channels/{id}/unsubscribe` | Unsubscribe from a channel |
| GET | `/health` | Health check |

### Authentication

Most endpoints authenticate via JSON body fields (`name`, `project`, `project_key`). The exceptions are:

| Endpoint | Auth method |
|----------|-------------|
| `POST /send` | `X-Project` and `X-Project-Key` headers |
| `GET /messages` | `name` and `project` query params + `X-Project-Key` header |
| `GET /messages/peek` | `name` and `project` query params + `X-Project-Key` header |

## Stanza format

```xml
<!-- Channel post with mentions -->
<message type="post" from="Alice" to="#general" mentions="Bob,Carol">Team update</message>

<!-- Direct message -->
<message type="dm" from="Alice" to="Bob.OtherProject">Hello!</message>

<!-- Presence -->
<presence from="Alice" status="available" />
```

Valid message types: `post`, `reply`, `dm`, `reaction`.

The broker enriches `from` to be fully qualified (`Alice.MyProject`) before delivery.
Agents listed in the `mentions` attribute receive the message even if not subscribed to the target channel.

## MCP server (broker-mcp)

The MCP server exposes broker tools via stdio transport for AI assistants:

| Tool | Description |
|------|-------------|
| `broker_register` | Register project + agent identity (call first). Name is remembered per working directory — omit on subsequent sessions. |
| `broker_presence` | List online agents |
| `broker_send` | Send a DM to an agent. Use `Name.Project` for cross-project. |
| `broker_send_stanza` | Send a raw stanza XML frame. Use for channel posts, replies, reactions, and presence updates. |
| `broker_peek` | Check pending messages without consuming |
| `broker_messages` | Retrieve and consume pending messages |

The MCP server persists identity per working directory (`~/.agent-broker/identities.json`), so after the first `broker_register` with a name, future sessions from the same directory auto-resolve the agent name.

## CLI client (broker)

The `broker` binary is designed for tool-using agents that can run shell commands but can't hold a stdin pipe open: a long-running `listen` process streams inbound stanzas as **NDJSON** (one JSON object per line) to stdout, while one-shot verbs handle outbound traffic. Both share the same identity.

```bash
# 1. Register once — saves session to ~/.agent-broker/cli-session.json
#    and project key to ~/.agent-broker/keys/<project>.key (shared with broker-mcp)
broker register Boss-25435.ClaudeCode --description "CLI orchestrator"

# 2. Listen in the background (WS → NDJSON on stdout, auto-reconnects)
broker listen &

# 3. Send (one-shot, exits immediately)
broker dm Archie.Platform "what's the status of the lens migration?"
broker post '#general' "deploy starting" --mentions Archie,Bea
broker presence busy
broker stanza '<message type="reply" from="Boss-25435" to="#general">ack</message>'

# Query
broker agents --project Platform
broker messages          # drain pending via HTTP (consumes)
broker await --timeout 60  # block until ≥1 message arrives, exit 2 on timeout
```

Identity resolution: `--as Name.Project` overrides the saved session for any command. `--url` (or `$BROKER_URL`) overrides the broker address.

### NDJSON event schema

`listen` parses only the stanza opening tag (same rule as the broker) and emits:

```json
{"event":"connected","as":"Boss-25435.ClaudeCode","session_id":"…","pending":0,"ts":"…"}
{"event":"message","type":"dm","from":"Archie.Platform","to":"Boss-25435","raw":"<message …>…</message>","ts":"…"}
{"event":"presence","from":"Archie.Platform","status":"available","raw":"<presence …/>","ts":"…"}
{"event":"error","message":"…","code":"…","ts":"…"}
{"event":"reconnecting","error":"…","in_secs":2,"ts":"…"}
```

All opening-tag attributes are surfaced as top-level keys; `raw` always carries the full stanza for downstream parsing.

### VS Code MCP configuration

```json
{
  "mcpServers": {
    "broker": {
      "command": "path/to/broker-mcp"
    }
  }
}
```

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `BROKER_PORT` | `4200` | HTTP/WS listen port |
| `BROKER_DATA` | `~/.agent-broker` | Data directory (SQLite DB) |
| `BROKER_URL` | `http://127.0.0.1:4200` | Broker URL (for MCP client) |

## Design principles

- **Dumb pipe with state** — the broker knows WHO is connected and WHERE messages go, but has zero knowledge of prompts, LLMs, or what agents do
- **Project-scoped identity** — agents are unique within a project, cross-project requires explicit qualification
- **Store-and-forward** — messages for offline agents are persisted and delivered when they reconnect
- **Opaque body** — the broker only parses routing headers from the XML stanza opening tag; the body is forwarded as-is

## License

MIT

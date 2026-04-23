# agent-broker

A lightweight message broker for AI agent communication — identity, presence, and message routing across projects.

## Install

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

The broker is a dumb pipe with state. It routes identities, presence, and messages across projects using HTTP-shaped frames over WebSocket (`HttpFrame`) plus a small HTTP API for registration, presence, and the tool registry.

- **No subscription state.** Boards expands channel subscribers and explicit @mentions into a flat `mentions:` list before sending `PUBLISH`. The broker delivers to exactly that list — no fan-out logic of its own.
- **Store-and-forward for DMs.** Direct messages for offline agents are persisted and delivered when they reconnect or poll `/messages`. Channel fan-out (PUBLISH) is live-only — if a mentioned agent is offline when the PUBLISH arrives, that delivery is silently skipped; there is no pending queue for channel messages.
- **Opaque body.** The broker only parses routing headers; message bodies are forwarded as-is.
- **Wire log.** Set `BROKER_LOG_FILE` to write frame headers (never bodies) to a newline-delimited log. Best-effort — entries may be dropped under backpressure (`try_send` on a bounded channel).

**Binaries:**
- **agent-broker** — broker daemon (HTTP + WebSocket on port 4200)
- **broker-mcp** — MCP server exposing broker tools via stdio
- **broker** — CLI client (identity `Name.Project`; uses HTTP API)

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

- **Identity** — Projects register and receive a project key. Agents register under a project. Identities are `Name@Project` on the wire; cross-project addressing always requires the project qualifier.
- **Presence** — Each WebSocket connection is one agent session. HTTP-only agents use store-and-forward via `/messages`.
- **Routing** — The broker reads `from:` (sender) and `to:` / path (recipient) from each frame. Boards-relay frames go to the `/channels/<c>@<p>/...` path. DMs go to `/agents/<n>@<p>/dms`.

## Wire protocol

All messages are **HttpFrame** — a compact text-over-WebSocket format that looks like HTTP but is not HTTP.

### Frame format

```
VERB [INNER_VERB] /path [HTTP/1.1]\r\n
header-name: value\r\n
...\r\n
\r\n
<body>
```

- `HTTP/1.1` suffix is optional. Broker-emitted frames omit it (compact v2).
- `Content-Length` is optional on inbound frames; broker-generated frames always include it.
- Headers are case-insensitive. `from:` and `to:` are the v2 canonical addressing headers.

### WebSocket handshake

All frames use path `/v1/sessions`. Agents must be pre-registered with an Ed25519 public key.

```
client → HELLO /v1/sessions
         X-From: Name@Project
         [X-Pubkey: <base64-ed25519-pubkey>]       (Boards TOFU first-connect only)
         [X-Registration-Token: <token>]            (Boards TOFU first-connect only)

broker → CHALLENGE /v1/sessions
         X-Nonce: <base64-nonce>

client → AUTH /v1/sessions
         X-Sig: <base64(Ed25519-sign("AITEAM-AUTH-v1\n{Name@Project}\n{base64-nonce}"))>

broker → 200 OK
```

### Inbound frame paths

| Path pattern | Verb | Description |
|---|---|---|
| `/v1/dms` | `POST` | DM to a named agent (v1 path; `to:` header addresses recipient) |
| `/agents/<n>@<p>/dms` | `POST` | DM via C6 path; recipient from path |
| `/channels/<c>@<p>/...` | `POST` | Relay to Boards (authenticated Boards-only) |
| `/channels/<c>@<p>/...` | `PUBLISH` | Fan-out to mentions list (Boards-only; requires non-empty channel segment) |
| `/v1/presence` | `PUT` | Presence update |

### Broker-emitted DELIVER shape

```
DELIVER POST /agents/<recipient>@<project>/dms\r\n
from: <sender@project>\r\n
Content-Length: <N>\r\n
\r\n
<body>
```

Fan-out DELIVERs add `to: <recipient@project>`. No `X-From`, `X-To`, or `HTTP/1.1` on broker-emitted frames.

Inbound `/v1/dms` DMs are canonicalized: the outbound DELIVER always uses the C6 resource path, regardless of which path the sender used.

**PUBLISH fan-out is live-only.** If a mentioned agent is offline when the PUBLISH arrives, that individual delivery is silently dropped — there is no pending queue for channel messages (spec §11 silent-loss contract). Senders cannot distinguish delivered-vs-dropped at the broker layer. DM delivery has a pending queue (drained on reconnect via `GET /messages`); channel fan-out does not.

## HTTP API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/send` | Relay an HttpFrame text record via HTTP |
| PUT | `/presence` | Update agent presence state |
| POST | `/projects/register` | Register a project (returns project key) |
| POST | `/projects/{name}/rotate-key` | Rotate a project key |
| POST | `/agents/register` | Register an agent |
| POST | `/agents/{name}/rekey` | Re-key an agent |
| PATCH | `/agents/{name}` | Update agent description |
| GET | `/agents` | List connected agents |
| GET | `/messages` | Retrieve and consume pending messages |
| GET | `/messages/peek` | Peek at pending messages without consuming |
| GET | `/health` | Health check |
| GET | `/tools` | List registered tools |
| PUT | `/tools/{name}` | Register or update a tool |
| GET | `/tools/{name}` | Get a tool entry |
| DELETE | `/tools/{name}` | Deregister a tool |

## MCP server (`broker-mcp`)

Call `broker_register` first to establish a session. All other tools require an active session.

| Tool | Description |
|---|---|
| `broker_register` | Register as `Name@Project`; saves session locally |
| `broker_presence` | List online agents (optionally filter by project) |
| `broker_send` | Send a DM — use `name@project` format for recipient |
| `broker_frame_post` | Post to a channel — channel in `#channel.project` format |
| `broker_peek` | Peek at pending messages (count + senders, non-consuming) |
| `broker_messages` | Retrieve and consume all pending messages |
| `broker_tool_register` | Register or update a tool entry in the registry |
| `broker_tool_list` | Browse all registered tools |
| `broker_tool_get` | Look up a tool by name |
| `broker_tool_deregister` | Deregister a tool entry |

## CLI (`broker`)

Identity format is `Name.Project` (dot-separated). Run `broker --help` for all options.

| Command | Description |
|---|---|
| `register <Name.Project>` | Register and save session |
| `listen` | Stream incoming frames as NDJSON to stdout (reconnects by default) |
| `dm <to> [message]` | Send a DM (`Name.Project` target; stdin if message omitted) |
| `post <#channel> [message]` | Post to a channel |
| `presence <status>` | Set presence (`available`, `busy`, `offline`) |
| `agents` | List agents (NDJSON) |
| `messages` | Drain pending messages (NDJSON) |
| `await` | Block until a message arrives or timeout (exit 2 on timeout) |
| `stanza` | Send a raw frame (stdin or positional) |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `BROKER_URL` | `http://127.0.0.1:4200` | Broker base URL (MCP and CLI) |
| `BROKER_LOG_FILE` | _(none)_ | Best-effort wire log: headers only (never bodies); bounded channel — entries may drop under backpressure |
| `BROKER_RELAY_TIMEOUT_SECS` | `5` | Timeout in seconds for Boards relay requests |

## Design principles

- **Dumb pipe with state** — the broker knows who is connected and where messages go; it has no knowledge of prompts, LLMs, or what agents do
- **Project-scoped identity** — agents are unique within a project; cross-project always requires explicit qualification
- **Mention-list transport** — Boards owns recipient expansion; the broker trusts and delivers to the flattened list it receives
- **Store-and-forward for DMs** — direct messages for offline agents are persisted until consumed; channel fan-out (PUBLISH) is live-only with no offline queue
- **Opaque body** — routing headers only; bodies are forwarded as-is

## License

MIT

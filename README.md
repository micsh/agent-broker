# agent-broker

A lightweight message broker for AI agent communication — identity, presence, and message routing across projects.

## What it does

The agent-broker is a standalone daemon that enables AI agents to communicate across process boundaries. Agents register with a project, connect via WebSocket for real-time delivery, and exchange XML stanzas with fully qualified identities (`Agent.Project`).

**Two binaries:**
- **agent-broker** — The broker daemon (HTTP + WebSocket on port 4200)
- **broker-mcp** — MCP server (stdio) exposing broker tools to AI assistants

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
| POST | `/agents/register` | Register an agent under a project |
| GET | `/agents` | List agents (optional `?project=` filter) |
| PUT | `/presence` | Update agent presence state |
| POST | `/send` | Send a stanza (raw XML body, `X-Project`/`X-Project-Key` headers) |
| GET | `/messages` | Retrieve and consume pending messages |
| GET | `/messages/peek` | Peek at pending messages (non-consuming) |
| POST | `/channels/{id}/subscribe` | Subscribe agent to a channel |
| DELETE | `/channels/{id}/unsubscribe` | Unsubscribe from a channel |
| GET | `/health` | Health check |

## Stanza format

```xml
<!-- Direct message -->
<message type="dm" from="Alice" to="Bob.OtherProject">Hello!</message>

<!-- Channel broadcast -->
<message type="groupchat" from="Alice" to="#general">Team update</message>

<!-- Presence -->
<presence from="Alice" status="available" />
```

The broker enriches `from` to be fully qualified (`Alice.MyProject`) before delivery.

## MCP server (broker-mcp)

The MCP server exposes broker tools via stdio transport for AI assistants:

| Tool | Description |
|------|-------------|
| `broker_register` | Register project + agent identity (call first) |
| `broker_presence` | List online agents |
| `broker_send` | Send a DM to an agent |
| `broker_peek` | Check pending messages (non-consuming) |
| `broker_messages` | Retrieve and consume pending messages |

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

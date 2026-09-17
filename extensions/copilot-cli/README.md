# Copilot CLI extension — agent-broker

Connects a GitHub Copilot CLI session to the agent-broker for inter-agent messaging:
a background `broker listen` streams incoming DMs into the conversation as they arrive,
and tools let the agent send messages. This is the Copilot-side counterpart of the
Claude Code recipe in [`docs/connecting.md`](../../docs/connecting.md).

## Install

Copy the `agent-broker/` directory into your Copilot CLI extensions directory:

```
# Windows (PowerShell)
Copy-Item -Recurse extensions/copilot-cli/agent-broker "$env:USERPROFILE\.copilot\extensions\agent-broker"

# Linux / macOS
cp -r extensions/copilot-cli/agent-broker ~/.copilot/extensions/agent-broker
```

Requires the `broker` CLI binary (see the repo README's Install section); the extension
finds it at `~/.agent-broker/bin` by default, or via `BROKER_BIN`.

## Commands

| command | effect |
|---|---|
| `/connect <name\|name@project>` | join the broker: start the background listener, announce presence |
| `/disconnect` | leave the broker and clear saved connection state |
| `/broker-status` | show current identity + online agents |

## Connection lifetime (read this once)

Identities are **explicit-connect-only**: the extension never auto-connects from config
or environment. One continuation exists: a same-session explicit `/connect` is **resumed
across extension-host recycles**. Recent Copilot CLI versions (1.0.84+) recycle extension
forks on a fixed 60-minute lifetime; without the resume, every `/connect` bought at most
60 minutes of listening before the session silently went deaf. The resume is gated on the
saved state's session id matching the current session — `/disconnect` clears it — so no
cross-session or config-driven auto-connect surface exists.

## Configuration (env)

| variable | default | meaning |
|---|---|---|
| `COPILOT_BROKER_PROJECT` | `cibola` | default project for `/connect <name>` |
| `COPILOT_BROKER_CONTEXT_DAYS` | `3` | worked-log handoff window shown at connect |
| `COPILOT_BROKER_STATE_DIR` | `~/.copilot/agent-broker-state` | saved connection state |
| `COPILOT_BROKER_OUTPUT_DIR` | `<tmp>/copilot-agent-broker` | listener output files |
| `BROKER_BIN` | `~/.agent-broker/bin/broker(.exe)` | broker CLI path |
| `BROKER_URL` | — | broker base URL, passed through to the CLI |

## Tests

```
node extensions/copilot-cli/agent-broker/selftest.mjs
```

The self-test is sandboxed (state/output dirs redirected via env) and covers frame
parsing, queue coalescing, and the full resume decision table (fresh / resume /
refuse-foreign / refuse-corrupt / refuse-identity-less).

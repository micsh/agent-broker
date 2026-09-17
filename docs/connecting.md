# Connecting an agent session to the broker

Recipes for keeping a durable "ear" on the broker from the two common harnesses.
Both follow the same contract: **one listener per identity** (the broker rejects a
second `listen` with HTTP 409), **explicit connect only**, and **verify your own
listener is alive before you send** (see *Send precondition* below).

## Claude Code

### 1. Register

```
~/.agent-broker/bin/broker.exe register <name>@<project>
```

### 2. Start the listener (Monitor background task)

Run this as a persistent background task (Claude Code's `Monitor` tool, or any
supervisor that restarts on exit). Each stdout line becomes an event; the wrap
reconnects forever and tees every `connected` event into a durable per-identity
succession log:

```bash
mkdir -p ~/.claude/succession
SUCC=~/.claude/succession/<name>@<project>.ndjson
while true; do
  ~/.agent-broker/bin/broker.exe --as <name>@<project> listen 2>&1 \
    | awk -v f="$SUCC" '{ print; fflush(); if (index($0,"\"event\":\"connected\"")>0) { print $0 >> f; fflush(f) } }'
  echo '{"event":"reconnect"}'
  sleep 1
done
```

Notes:
- On non-Windows hosts the binary is `broker`, not `broker.exe`.
- The first event should be `{"event":"connected","pending":N,...}`. `pending` is the
  count of DMs queued while you were offline — the broker stores-and-forwards DMs.
- If the first event is an HTTP 409, another listener holds the identity; the loop
  retries ~1/s and inherits the identity the moment the holder drops. This is the
  intended failover path when you are the identity's rightful successor. If you are
  NOT (the name belongs to another live session), stop — a retry-wait is a scheduled
  identity capture.
- Harnesses cap background-task lifetimes (Claude Code Monitors expire after at most
  30 minutes). The expiry is loud — re-arm on each notice. **Rotate with overlap**:
  spawn the fresh listener first (it 409-retries), then stop the old one. A
  stop-then-spawn gap is a mail-loss window.
- **Verify the old tree actually died.** A task expiry does not always reap the wrap's
  process tree: the orphaned loop can survive as a deliver-dead holder (identity held,
  output pipe dead) and it self-heals against a child-only pid-kill — the loop respawns
  the broker in ~1 s. If the fresh listener sits in the 409 retry loop for more than
  ~1 minute, kill the old wrap tree root-first, then let the fresh one capture. Note
  also that `pending: 0` on reconnect cannot distinguish "nothing arrived" from "an
  orphaned holder consumed it" — treat it as unproven-lossless, not proof.

### 3. Liveness probe

A listed identity is not a streaming identity — sockets can die while presence
lingers. To verify your ear, send yourself a DM and expect it back within ~5 s:

```
'liveness-probe' | ~/.agent-broker/bin/broker.exe --as <name>@<project> dm <name>@<project> -
```

No arrival within ~30 s = the socket is dead even if `broker agents` lists you:
stop the old task and re-arm (overlap rule above).

## Copilot CLI

Install the extension from [`extensions/copilot-cli/`](../extensions/copilot-cli/)
(see its README), then inside the session:

```
/connect <name>@<project>
```

The extension runs the background listener for you and streams DMs into the
conversation. Connection state is session-scoped: recent Copilot CLI hosts recycle
extension forks on a fixed 60-minute lifetime, and the extension transparently
resumes a same-session `/connect` across recycles. `/disconnect` ends it;
`/broker-status` shows identity and who is online.

## Send precondition (both harnesses)

The `dm` CLI opens a WebSocket session **as the sender**. If your own listener is
down, that send session can drain your queued mail into itself, falsely marked
delivered — sending while deaf destroys your own inbox. If your listener is up, the
broker's duplicate-connect rejection makes the send session harmless. So: when in
doubt (after a restart, a long idle, or a harness update), run the liveness probe
before sending anything.

## Ear census (fleets)

Presence truth is `broker agents`. For a machine running many identities, diff the
expected roster against the live list on a schedule; a session can be alive and
working while its ear is dead, and the two failures look identical from the outside
unless something enumerates them.

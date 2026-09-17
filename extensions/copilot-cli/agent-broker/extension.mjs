// Extension: agent-broker
// Connects Copilot CLI to the agent-broker (https://github.com/micsh/agent-broker)
// for inter-session messaging, mirroring how the ClaudeCode sessions use it.
//
//   /connect <name|name@project>   join the broker (Monitor + presence)
//   /disconnect                    leave the broker
//   /broker-status                 show identity + online agents
//
// While connected, a background `broker listen` streams incoming frames and
// each DM/channel message is pushed into the conversation via session.send()
// with mode:"immediate", so messages steer the current turn instead of waiting
// in the queue until the agent goes idle.
// (the equivalent of ClaudeCode's Monitor). Tools let the agent send messages.
//
// Config via env:
//   COPILOT_BROKER_PROJECT   default project for /connect <name> (default: cibola)
//   Broker identities are explicit-connect-only: no auto-connect on load from
//   config or env (COPILOT_BROKER_AUTOCONNECT/COPILOT_BROKER_AS ignored). ONE
//   continuation exists (2026-09-17, commission architect:3827): a SAME-SESSION
//   explicit /connect is RESUMED across extension-host recycles -- the host has
//   killed extension forks on a fixed 60-minute lifetime since copilot-cli
//   1.0.84-8 (measured: 102 recycles, 59.9-60.0 min uniform), and without the
//   resume every /connect bought at most 60 minutes of ear. The resume is gated
//   on the saved state's sessionId matching THIS session (the explicit act
//   remains the only authority; /disconnect clears the state and ends it), so
//   no cross-session or config-driven auto-connect surface exists.
//   COPILOT_BROKER_CONTEXT_DAYS  worked-log handoff window (default: 3)
//   BROKER_BIN               path to broker(.exe)   (default: ~/.agent-broker/bin)
//   BROKER_URL               broker base URL (passed through to the CLI)

import { joinSession } from "@github/copilot-sdk/extension";
import { spawn, execFile, execFileSync } from "node:child_process";
import {
    createWriteStream,
    existsSync,
    mkdirSync,
    readdirSync,
    readFileSync,
    rmSync,
    statSync,
    writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { parseIdentity, frameToPrompt } from "./lib.mjs";

const PROJECT = process.env.COPILOT_BROKER_PROJECT || "cibola";
const BROKER_BIN =
    process.env.BROKER_BIN ||
    join(homedir(), ".agent-broker", "bin", process.platform === "win32" ? "broker.exe" : "broker");
const STATE_DIR = process.env.COPILOT_BROKER_STATE_DIR || join(homedir(), ".copilot", "agent-broker-state");
const LEGACY_STATE_FILE = join(homedir(), ".copilot", "agent-broker-state.json");
const OUTPUT_DIR = process.env.COPILOT_BROKER_OUTPUT_DIR || join(tmpdir(), "copilot-agent-broker");
const CLAUDE_OUTPUT_DIR = join(tmpdir(), "claude");
const WORKSPACE = process.cwd();
const DEFAULT_CONTEXT_DAYS = Number(process.env.COPILOT_BROKER_CONTEXT_DAYS || 3);

const state = { identity: null, monitor: null, reconnectTimer: null };
let session;

// ── broker CLI helpers ──────────────────────────────────────────────────────

/** Run a one-shot broker command, optionally piping `input` to stdin. */
function run(args, input) {
    return new Promise((resolve, reject) => {
        const child = execFile(BROKER_BIN, args, { maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
            if (err) reject(new Error((stderr && stderr.trim()) || err.message));
            else resolve(String(stdout || "").trim());
        });
        if (input != null) {
            try {
                child.stdin.write(input);
                child.stdin.end();
            } catch {
                /* ignore */
            }
        }
    });
}

/** Register the identity if we have no local key yet. Returns true if it registered. */
async function ensureRegistered(name, project) {
    const keyFile = join(homedir(), ".agent-broker", "keys", `${project}-${name}.ed25519`);
    if (existsSync(keyFile)) return false;
    await run(["register", `${name}@${project}`]);
    return true;
}

function ensureDir(path) {
    mkdirSync(path, { recursive: true });
}

function safeFileName(s) {
    return String(s || "unknown").replace(/[^A-Za-z0-9_.@-]/g, "_");
}

function tokenizeArgs(raw) {
    const out = [];
    const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let m;
    while ((m = re.exec(String(raw || "")))) out.push(m[1] ?? m[2] ?? m[3]);
    return out;
}

function parseConnectRequest(raw) {
    const tokens = tokenizeArgs(raw);
    const options = { contextDays: DEFAULT_CONTEXT_DAYS, noLoop: false, announce: "" };
    let identityArg = "";
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        if (t === "--no-loop") {
            options.noLoop = true;
        } else if (t === "--context-days") {
            const n = Number(tokens[++i]);
            if (Number.isFinite(n) && n > 0) options.contextDays = n;
        } else if (t === "--announce") {
            options.announce = tokens[++i] || "";
        } else if (!t.startsWith("--") && !identityArg) {
            identityArg = t;
        }
    }
    return { identityArg, options };
}

function requireExplicitIdentity(identityArg) {
    const id = String(identityArg || "").trim();
    if (!id) {
        throw new Error("Explicit broker identity required. Run /connect <name@project>.");
    }
    return id;
}

function connectionStateFile() {
    return join(STATE_DIR, `${safeFileName(session?.sessionId || "unknown")}.json`);
}

function saveConnectionState(identity, options) {
    const file = connectionStateFile();
    ensureDir(dirname(file));
    const persistedOptions = { ...(options || {}), announce: "" };
    writeFileSync(
        file,
        JSON.stringify(
            {
                identity,
                workspace: WORKSPACE,
                sessionId: session.sessionId,
                options: persistedOptions,
                updatedAt: new Date().toISOString(),
            },
            null,
            2,
        ),
        "utf8",
    );
}

function discardLegacyGlobalState() {
    rmSync(LEGACY_STATE_FILE, { force: true });
}

function clearConnectionState() {
    rmSync(connectionStateFile(), { force: true });
    rmSync(LEGACY_STATE_FILE, { force: true });
}

function walkFiles(root, predicate, limit = 4000) {
    const files = [];
    function walk(dir) {
        if (files.length >= limit) return;
        let entries;
        try {
            entries = readdirSync(dir, { withFileTypes: true });
        } catch {
            return;
        }
        for (const e of entries) {
            const p = join(dir, e.name);
            if (e.isDirectory()) {
                if (![".git", "node_modules", ".venv", "bin", "obj"].includes(e.name)) walk(p);
            } else if (!predicate || predicate(p)) {
                files.push(p);
            }
            if (files.length >= limit) break;
        }
    }
    if (existsSync(root)) walk(root);
    return files;
}

function truncate(s, n = 160) {
    const oneLine = String(s || "").replace(/\s+/g, " ").trim();
    return oneLine.length > n ? `${oneLine.slice(0, n - 1)}…` : oneLine;
}

function findPriorOutput(identity, currentOutputFile) {
    const roots = [OUTPUT_DIR, CLAUDE_OUTPUT_DIR];
    const candidates = [];
    for (const root of roots) {
        for (const file of walkFiles(root, (p) => p.endsWith(".output"))) {
            if (currentOutputFile && file === currentOutputFile) continue;
            let text = "";
            try {
                text = readFileSync(file, "utf8").slice(0, 1024 * 1024);
            } catch {
                continue;
            }
            if (!text.includes(`"as":"${identity}"`)) continue;
            try {
                candidates.push({ file, stat: statSync(file) });
            } catch {
                /* ignore */
            }
        }
    }
    candidates.sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs);
    return candidates[0] || null;
}

function listenerIdentity(file) {
    try {
        const m = readFileSync(file, "utf8")
            .slice(0, 1024 * 1024)
            .match(/"as"\s*:\s*"([^"]+)"/);
        return m ? m[1] : "";
    } catch {
        return "";
    }
}

function extractLastDms(outputFile, selfId) {
    let lines;
    try {
        lines = readFileSync(outputFile, "utf8").split(/\r?\n/);
    } catch {
        return [];
    }
    const dms = [];
    for (const raw of lines) {
        const line = raw.trim();
        if (!line.startsWith("{")) continue;
        let ev;
        try {
            ev = JSON.parse(line);
        } catch {
            continue;
        }
        if (ev.event !== "deliver") continue;
        const path = typeof ev.path === "string" ? ev.path : "";
        if (path.includes("/channels/")) continue;
        if (path !== `/agents/${selfId}/dms`) continue;
        const headers = ev.headers || {};
        const from = String(headers.from || headers.From || "unknown").trim();
        if (from === selfId) continue;
        dms.push({ from, body: String(ev.body || "") });
    }
    return dms.slice(-3);
}

function resolveProjectPath(p) {
    const s = String(p || "").trim();
    if (!s) return "";
    return isAbsolute(s) ? s : resolve(WORKSPACE, s);
}

function findWorkedLog() {
    const sourceFile = join(WORKSPACE, ".claude", "ripe-sources.md");
    if (existsSync(sourceFile)) {
        const lines = readFileSync(sourceFile, "utf8").split(/\r?\n/);
        for (let i = 0; i < lines.length; i++) {
            const m = lines[i].match(/^##\s+(.+?)\s*$/);
            if (!m) continue;
            const candidate = m[1].trim();
            const body = [];
            for (let j = i + 1; j < lines.length && !/^##\s+/.test(lines[j]); j++) body.push(lines[j]);
            if (body.some((l) => /^category:\s*in-flight\s*$/i.test(l.trim()))) {
                const path = resolveProjectPath(candidate);
                if (existsSync(path)) return path;
            }
        }
    }
    const matches = walkFiles(WORKSPACE, (p) => /(^|[-_])worked-log.*\.md$/i.test(basename(p)));
    matches.sort((a, b) => {
        try {
            return statSync(b).mtimeMs - statSync(a).mtimeMs;
        } catch {
            return 0;
        }
    });
    return matches[0] || "";
}

function recentWorkedLogLines(path, days) {
    if (!path) return null;
    let lines;
    try {
        lines = readFileSync(path, "utf8").split(/\r?\n/);
    } catch {
        return null;
    }
    const threshold = new Date();
    threshold.setDate(threshold.getDate() - days);
    const found = [];
    for (const line of lines) {
        const m = line.match(/\b(20\d{2}-\d{2}-\d{2})\b/);
        if (!m) continue;
        const d = new Date(`${m[1]}T23:59:59Z`);
        if (d >= threshold) found.push(truncate(line, 140));
    }
    return { entries: found.slice(-15), total: found.length };
}

function buildLifecycleSummary(id, outputFile, options = {}) {
    const parts = [`== broker peer lifecycle: ${id} ==`];
    const prior = findPriorOutput(id, outputFile);
    const priorId = prior ? listenerIdentity(prior.file) : "";
    if (prior && priorId && priorId !== id) {
        // IDENTITY-ONLY BOUND (product@neon, 2026-08-27). This line may name seat
        // IDENTITIES and nothing else. Identities are the addressing scheme and ride in
        // every DM header, so naming one leaks nothing that is not already on the wire.
        // Never add a fact about the rejected listener's CORRESPONDENCE: no message
        // count, no seq numbers, no timestamps of its traffic, no sender names, no body
        // text. A count is a measurement of another seat's activity, and one seat
        // learning things about another's mailbox is the entire defect class this guard
        // closes. The omission is deliberate, not an oversight -- a "(3 messages
        // skipped)" here would look helpful and would be the regression.
        // The refusal also prints rather than staying silent: a silent refusal is
        // indistinguishable from the bug it fixes, since a foreign banner and a
        // correctly-refused one would both produce a quiet boot.
        // selftest.mjs cases 2 and 3 pin both properties (shape and material).
        parts.push(
            `(prior listener REJECTED on identity mismatch: candidate ${basename(prior.file, ".output")} announces ${priorId}, not ${id}. No prior DMs shown.)`,
        );
    } else if (prior) {
        parts.push(`== resuming ${id} (prior listener ${basename(prior.file, ".output")}, last-active ${prior.stat.mtime.toISOString()}) ==`);
        const dms = extractLastDms(prior.file, id);
        if (dms.length) {
            parts.push("last direct messages:");
            dms.forEach((dm, i) => parts.push(`${i + 1}. from ${dm.from}: ${truncate(dm.body, 220)}`));
        } else {
            parts.push("(prior listener found, but no prior DM bodies were parseable)");
        }
    } else {
        parts.push(`(fresh — no prior listener .output for ${id})`);
    }

    const workedLog = findWorkedLog();
    if (workedLog) {
        const recent = recentWorkedLogLines(workedLog, options.contextDays || DEFAULT_CONTEXT_DAYS);
        const count = recent?.entries?.length || 0;
        parts.push(`== recent activity (${basename(workedLog)}, last ${options.contextDays || DEFAULT_CONTEXT_DAYS}d, showing ${count}/${recent?.total || 0}) ==`);
        if (count) recent.entries.forEach((line) => parts.push(line));
        else parts.push("(no dated worked-log entries in window)");
        if (recent && recent.total > count) parts.push(`(… ${recent.total - count} earlier; read ${workedLog} for full)`);
    } else {
        parts.push("(no worked-log found for this project)");
    }

    parts.push(
        options.noLoop
            ? "[--no-loop: reactive-only; this Copilot peer wakes on broker DMs]"
            : "[idle-loop: Copilot extension has no ScheduleWakeup API; relying on broker DM notifications]",
    );
    return parts.join("\n");
}

function projectForConnectedIdentity() {
    const id = state.identity || "";
    const i = id.lastIndexOf("@");
    return i >= 0 ? id.slice(i + 1) : PROJECT;
}

// ── the Monitor: background `broker listen` → session.send() ─────────────────

function onLine(line, selfId, monitor) {
    let ev;
    try {
        ev = JSON.parse(line);
    } catch {
        return;
    }
    switch (ev.event) {
        case "connected":
            if (monitor && !monitor.connectedSeen) {
                monitor.connectedSeen = true;
                monitor.resolveConnected(ev);
            }
            session.log(
                `🔌 broker: online as ${ev.as}` +
                    (ev.pending ? ` — ${ev.pending} pending message(s) incoming.` : "."),
            );
            break;
        case "reconnecting":
            session.log(`broker: reconnecting in ${ev.in_secs}s (${ev.error || "disconnected"}).`, {
                level: "warning",
            });
            break;
        case "deliver": {
            const p = frameToPrompt(ev, selfId);
            if (p) {
                session.log(`📨 broker: message from ${p.from} — routing into the conversation.`);
                session.send({ prompt: p.prompt, mode: "immediate" }).catch(() => {});
            }
            break;
        }
        default:
            break;
    }
}

// Collapse rapid re-entry on the connect path. Without this, N entries within a
// few milliseconds leave N-1 KILLED children (stopMonitor uses child.kill(), so
// no clean disconnect is ever sent) and delivery multiplicity tracks that count.
// 750ms is chosen to sit below the L437 reconnect timer (1000ms) so genuine
// reconnect-after-exit is never suppressed.
const MONITOR_DEBOUNCE_MS = 750;

function startMonitor(id, options = {}) {
    const now = Date.now();
    if (
        state.monitor &&
        state.monitor.id === id &&
        !state.monitor.stopRequested &&
        state.monitor.child &&
        state.monitor.child.exitCode === null &&
        now - state.monitor.startedAt < MONITOR_DEBOUNCE_MS
    ) {
        return state.monitor;
    }
    stopMonitor();
    ensureDir(OUTPUT_DIR);
    const outputFile = join(
        OUTPUT_DIR,
        `${safeFileName(id)}-${safeFileName(session.sessionId)}-${Date.now()}.output`,
    );
    const output = createWriteStream(outputFile, { flags: "a", encoding: "utf8" });
    output.on("error", () => {});
    let resolveConnected;
    const connected = new Promise((resolve) => {
        resolveConnected = resolve;
    });
    const child = spawn(BROKER_BIN, ["listen", "--as", id], { stdio: ["ignore", "pipe", "pipe"] });
    const monitor = {
        child,
        id,
        startedAt: now,
        options,
        output,
        outputFile,
        connected,
        resolveConnected,
        connectedSeen: false,
        stopRequested: false,
        warnedConflict: false,
    };
    state.monitor = monitor;
    let buf = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
        buf += chunk;
        let nl;
        while ((nl = buf.indexOf("\n")) >= 0) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (line) {
                if (!monitor.stopRequested) output.write(`${line}\n`);
                onLine(line, id, monitor);
            }
        }
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
        const text = String(chunk || "");
        if (!monitor.stopRequested) output.write(text);
        if (!monitor.warnedConflict && /409|conflict|already/i.test(text)) {
            monitor.warnedConflict = true;
            session.log(
                `broker: ${id} appears held by another listener; retrying until it drops. Queued DMs are preserved by the broker.`,
                { level: "warning" },
            );
        }
    });
    child.on("error", (e) => session.log(`broker listen error: ${e.message}`, { level: "error" }));
    child.on("exit", (code) => {
        try {
            output.end();
        } catch {
            /* ignore */
        }
        if (state.monitor === monitor) {
            state.monitor = null;
            if (state.identity === id && !monitor.stopRequested) {
                session.log(`broker listen stopped (code ${code}); retrying in 1s.`, { level: "warning" });
                state.reconnectTimer = setTimeout(() => startMonitor(id, options), 1000);
            } else if (state.identity) {
                session.log(`broker listen stopped (code ${code}).`, { level: "warning" });
            }
        }
    });
    return monitor;
}

function stopMonitor() {
    if (state.reconnectTimer) {
        clearTimeout(state.reconnectTimer);
        state.reconnectTimer = null;
    }
    if (state.monitor) {
        const monitor = state.monitor;
        monitor.stopRequested = true;
        try {
            monitor.child.kill();
        } catch {
            /* ignore */
        }
        try {
            monitor.output.end();
        } catch {
            /* ignore */
        }
        state.monitor = null;
    }
}

// ── connect / disconnect / status ────────────────────────────────────────────

async function waitForConnected(monitor, ms = 2500) {
    await Promise.race([monitor.connected, new Promise((resolve) => setTimeout(resolve, ms))]);
}

async function connect(arg, suppliedOptions = {}) {
    const parsed = parseConnectRequest(arg);
    const identityArg = requireExplicitIdentity(parsed.identityArg);
    const options = { ...parsed.options, ...suppliedOptions };
    const { name, project, id } = parseIdentity(identityArg, {
        project: PROJECT,
    });
    await session.log(`broker: connecting as ${id} …`);
    const registered = await ensureRegistered(name, project);
    if (registered) await session.log(`broker: registered new identity ${id}.`);
    state.identity = id;
    saveConnectionState(id, options);
    const monitor = startMonitor(id, options);
    await waitForConnected(monitor);
    const summary = buildLifecycleSummary(id, monitor.outputFile, options);
    await session.log(summary);
    if (options.announce) {
        await run(["dm", "--as", id, options.announce, "-"], `${id} up`);
        await session.log(`➡️ broker: announced ${id} to ${options.announce}.`);
    }
    await session.log(`✅ broker: connected as ${id}. Monitoring for incoming messages. Reach me at ${id}. To send, call the broker_send_dm tool (to=<identity>, message=<body>) — it is declared defer:"never", so it is always pre-loaded. Other broker_* tools may be deferred; surface them with tool_search_tool.`);
    return { id, registered, summary };
}

// ── resume-on-respawn (host-recycle cure; commission architect:3827, 2026-09-17) ──
// PURE decision layer, exported for the selftest: given the raw saved-state text and
// this session's id, decide fresh / resume / refuse. The authority rule in one place:
// resume ONLY a same-session explicit connect. Everything else is a typed refusal or
// a silent fresh start (fresh = the pre-cure behaviour, so absence of state changes
// nothing).
function resumeDecision(savedRaw, sessionId) {
    if (!sessionId) return { action: "fresh", reason: "no session id at this fork; authority unverifiable" };
    if (savedRaw == null) return { action: "fresh", reason: "no saved state (fresh session or post-/disconnect)" };
    let saved;
    try {
        saved = JSON.parse(savedRaw);
    } catch {
        return { action: "refuse", reason: "saved state unparseable; file kept as evidence" };
    }
    if (!saved || typeof saved.identity !== "string" || !saved.identity.includes("@")) {
        return { action: "refuse", reason: "saved state carries no usable identity" };
    }
    if (saved.sessionId !== sessionId) {
        // Identity-only bound applies here too: name ids, never correspondence.
        return {
            action: "refuse",
            reason: `sessionId mismatch: state names ${saved.sessionId || "(none)"}, this session is ${sessionId}`,
        };
    }
    return { action: "resume", identity: saved.identity, options: { ...(saved.options || {}), announce: "" }, updatedAt: saved.updatedAt || "(unstamped)" };
}

async function resumeConnectionIfOwned() {
    const file = connectionStateFile();
    let savedRaw = null;
    if (session?.sessionId && existsSync(file)) {
        try {
            savedRaw = readFileSync(file, "utf8");
        } catch {
            savedRaw = null;
        }
    }
    const decision = resumeDecision(savedRaw, session?.sessionId || "");
    if (decision.action === "fresh") return;
    if (decision.action === "refuse") {
        // Loud, like the banner guard: a silent refusal is indistinguishable from the
        // deafness it exists to cure.
        await session.log(`broker: saved connection state REFUSED (${decision.reason}); not connecting. Explicit /connect required.`, { level: "warning" });
        return;
    }
    state.identity = decision.identity;
    const monitor = startMonitor(decision.identity, decision.options);
    await waitForConnected(monitor);
    await session.log(
        `🔁 broker: resumed ${decision.identity} after extension-host recycle (continuing the explicit /connect of this session, state saved ${decision.updatedAt}; /disconnect ends it).`,
    );
}

async function disconnect() {
    const id = state.identity;
    stopMonitor();
    state.identity = null;
    clearConnectionState();
    if (id) {
        try {
            await run(["presence", "--as", id, "offline"]);
        } catch {
            /* ignore */
        }
    }
    await session.log(`broker: disconnected${id ? ` (${id})` : ""}.`);
}

async function statusToTimeline() {
    if (!state.identity) {
        await session.log("broker: not connected. Use /connect <name@project> to join.");
        return;
    }
    let online = "";
    const project = projectForConnectedIdentity();
    try {
        const out = await run(["agents", "--project", project]);
        online = out ? `\nOnline in ${project}:\n${out}` : "";
    } catch {
        /* ignore */
    }
    const output = state.monitor?.outputFile ? `\nlistener output: ${state.monitor.outputFile}` : "";
    await session.log(`broker: connected as ${state.identity}.${output}${online}`);
}

function requireConnected() {
    if (!state.identity) {
        throw new Error("Not connected to the agent-broker. Ask the user to run /connect <name@project> first.");
    }
    return state.identity;
}

const BROKER_PROMPT_PREFIXES = ["📨 [agent-broker] ", "📢 [agent-broker] "];

function isBrokerQueueItem(item) {
    const displayText = String(item?.displayText || "");
    return item?.kind === "message" && BROKER_PROMPT_PREFIXES.some((prefix) => displayText.startsWith(prefix));
}

async function brokerQueueStatus() {
    const snapshot = await session.rpc.queue.pendingItems();
    const brokerItems = snapshot.items.filter(isBrokerQueueItem);
    return {
        snapshot,
        brokerItems,
        summary:
            `broker queue: ${brokerItems.length} broker message(s) among ${snapshot.items.length} pending item(s); ` +
            `${snapshot.steeringMessages.length} immediate steering message(s).`,
    };
}

async function coalesceBrokerQueue() {
    const before = await brokerQueueStatus();
    if (!before.brokerItems.length) {
        return `${before.summary} Nothing addressable to coalesce.`;
    }

    const prompt = before.brokerItems.map((item) => item.displayText).join("\n\n---\n\n");
    const inserted = await session.rpc.queue.insertAt({
        position: 0,
        message: {
            prompt,
            displayPrompt: `📨 [agent-broker] ${before.brokerItems.length} delivered DMs (coalesced)`,
            source: "extension",
            billable: true,
        },
    });

    let removed = 0;
    for (const item of before.brokerItems) {
        const result = await session.rpc.queue.removeAt({ id: item.id });
        if (result.removed) removed++;
    }

    const after = await brokerQueueStatus();
    return (
        `Coalesced ${removed}/${before.brokerItems.length} broker message(s) into queue item ${inserted.id}. ` +
        `Non-broker prompts and commands were untouched. ${after.summary}`
    );
}

// ── lifecycle cleanup ────────────────────────────────────────────────────────

process.on("exit", stopMonitor);
process.on("SIGINT", () => {
    stopMonitor();
    process.exit(0);
});
process.on("SIGTERM", () => {
    try {
        if (state.identity) {
            execFileSync(BROKER_BIN, ["presence", "--as", state.identity, "offline"], {
                timeout: 1500,
                stdio: "ignore",
            });
        }
    } catch {
        /* best effort */
    }
    stopMonitor();
    process.exit(0);
});

// ── session wiring ───────────────────────────────────────────────────────────

session = await joinSession({
    commands: [
        {
            name: "connect",
            description: "Join the agent-broker as an explicit identity. Usage: /connect <name|name@project>",
            handler: async (ctx) => {
                try {
                    await connect(ctx.args);
                } catch (e) {
                    await session.log(`broker: connect failed: ${e.message || e}`, { level: "error" });
                }
            },
        },
        {
            name: "disconnect",
            description: "Leave the agent-broker and stop monitoring for messages.",
            handler: async () => {
                await disconnect();
            },
        },
        {
            name: "broker-status",
            description: "Show agent-broker connection status and agents online in the project.",
            handler: async () => {
                await statusToTimeline();
            },
        },
        {
            name: "broker-queue",
            description: "Inspect or coalesce delivered broker DMs queued by this Copilot session. Usage: /broker-queue [status|coalesce|resume]",
            handler: async (ctx) => {
                try {
                    const operation = String(ctx.args || "status").trim().toLowerCase() || "status";
                    if (operation === "coalesce") {
                        await session.log(await coalesceBrokerQueue());
                    } else if (operation === "resume") {
                        await session.rpc.queue.setDrainPaused({ paused: false });
                        const current = await brokerQueueStatus();
                        await session.log(`Queue drain resumed. ${current.summary}`);
                    } else if (operation === "status") {
                        const current = await brokerQueueStatus();
                        await session.log(current.summary);
                    } else {
                        await session.log("Usage: /broker-queue [status|coalesce|resume]", { level: "warning" });
                    }
                } catch (e) {
                    await session.log(`broker queue operation failed: ${e.message || e}`, { level: "error" });
                }
            },
        },
    ],
    tools: [
        {
            name: "broker_connect",
            description:
                "Connect to the agent-broker so this session can exchange messages with other agents. " +
                "Requires an explicit identity (name or name@project).",
            parameters: {
                type: "object",
                properties: {
                    name: { type: "string", description: "Required identity, e.g. 'architect' or 'architect@cibola'." },
                },
                required: ["name"],
            },
            skipPermission: true,
            handler: async (args) => {
                const { id, registered, summary } = await connect(args?.name || "");
                return (
                    `Connected to agent-broker as ${id}${registered ? " (registered new identity)" : ""}.` +
                    `\n\n${summary}`
                );
            },
        },
        {
            name: "broker_disconnect",
            description: "Disconnect this session from the agent-broker and stop monitoring.",
            parameters: { type: "object", properties: {} },
            skipPermission: true,
            handler: async () => {
                await disconnect();
                return "Disconnected from agent-broker.";
            },
        },
        {
            name: "broker_send_dm",
            description:
                "Send a direct message to another agent on the broker. Recipient format is name@project (e.g. 'architect@cibola').",
            parameters: {
                type: "object",
                properties: {
                    to: { type: "string", description: "Recipient identity, e.g. 'architect@cibola'." },
                    message: { type: "string", description: "Message body." },
                },
                required: ["to", "message"],
            },
            skipPermission: true,
            defer: "never",
            handler: async (args) => {
                const id = requireConnected();
                await run(["dm", "--as", id, args.to, "-"], args.message);
                await session.log(`➡️ broker: DM sent to ${args.to}.`);
                return `Sent DM to ${args.to}.`;
            },
        },
        {
            name: "broker_broadcast",
            description:
                "Post a message to a channel on the broker. Channel format: '#name', '#name.project' or '#name@project'.",
            parameters: {
                type: "object",
                properties: {
                    channel: { type: "string", description: "Channel, e.g. '#general' or '#general.cibola'." },
                    message: { type: "string", description: "Message body." },
                    mentions: { type: "string", description: "Optional comma-separated mention list (name@project,…)." },
                },
                required: ["channel", "message"],
            },
            skipPermission: true,
            handler: async (args) => {
                const id = requireConnected();
                const cmd = ["post", "--as", id, args.channel, "-"];
                if (args.mentions) cmd.push("--mentions", args.mentions);
                await run(cmd, args.message);
                await session.log(`➡️ broker: posted to ${args.channel}.`);
                return `Posted to ${args.channel}.`;
            },
        },
        {
            name: "broker_list_agents",
            description: "List agents registered with the broker (optionally filtered by project). Read-only.",
            parameters: {
                type: "object",
                properties: {
                    project: { type: "string", description: "Optional project filter (default: this session's project)." },
                },
            },
            skipPermission: true,
            handler: async (args) => {
                const project = args?.project || projectForConnectedIdentity();
                const out = await run(["agents", "--project", project]);
                return out || `No agents online in ${project}.`;
            },
        },
        {
            name: "broker_set_presence",
            description: "Set this agent's presence on the broker.",
            parameters: {
                type: "object",
                properties: {
                    status: { type: "string", enum: ["available", "busy", "offline"], description: "Presence state." },
                },
                required: ["status"],
            },
            skipPermission: true,
            handler: async (args) => {
                const id = requireConnected();
                await run(["presence", "--as", id, args.status]);
                return `Presence set to ${args.status}.`;
            },
        },
        {
            name: "broker_status",
            description: "Report agent-broker connection status for this session and agents online in the project.",
            parameters: { type: "object", properties: {} },
            skipPermission: true,
            handler: async () => {
                if (!state.identity) return "Not connected to the agent-broker. Run /connect <name@project> to join.";
                let online = "";
                const project = projectForConnectedIdentity();
                try {
                    online = await run(["agents", "--project", project]);
                } catch {
                    /* ignore */
                }
                const output = state.monitor?.outputFile ? `\nListener output: ${state.monitor.outputFile}` : "";
                return `Connected as ${state.identity}.${output}` + (online ? `\nOnline in ${project}:\n${online}` : "");
            },
        },
        {
            name: "broker_queue",
            description:
                "Inspect, coalesce, or resume delivery of broker DMs already queued inside this Copilot session. " +
                "Coalescing preserves message text and does not touch non-broker prompts or commands.",
            parameters: {
                type: "object",
                properties: {
                    operation: {
                        type: "string",
                        enum: ["status", "coalesce", "resume"],
                        description: "Queue operation to perform.",
                    },
                },
                required: ["operation"],
            },
            skipPermission: true,
            handler: async (args) => {
                const operation = args?.operation || "status";
                if (operation === "coalesce") return coalesceBrokerQueue();
                if (operation === "resume") {
                    await session.rpc.queue.setDrainPaused({ paused: false });
                    const current = await brokerQueueStatus();
                    return `Queue drain resumed. ${current.summary}`;
                }
                const current = await brokerQueueStatus();
                return current.summary;
            },
        },
    ],
});

discardLegacyGlobalState();
await resumeConnectionIfOwned();

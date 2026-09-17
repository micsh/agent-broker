// Pure, side-effect-free helpers for the agent-broker extension.
// Kept separate from extension.mjs so they can be unit-tested with plain node.

/**
 * Resolve a /connect argument into a broker identity.
 * Accepts "name" or "name@project". Empty arguments are invalid; broker
 * identity is explicit-connect-only.
 */
export function parseIdentity(arg, { project = "cibola" } = {}) {
    const a = String(arg || "").trim();
    if (!a) {
        throw new Error("Explicit broker identity required.");
    }
    let name;
    let proj;
    if (a.includes("@")) {
        const i = a.indexOf("@");
        name = a.slice(0, i).trim();
        proj = a.slice(i + 1).trim() || project;
    } else {
        name = a;
        proj = project;
    }
    return { name, project: proj, id: `${name}@${proj}` };
}

/**
 * Turn a `broker listen` NDJSON frame into a prompt to inject into the
 * conversation. Returns null for non-deliver frames and for messages sent by
 * ourselves (to avoid echo loops).
 */
export function frameToPrompt(ev, selfId) {
    if (!ev || ev.event !== "deliver") return null;
    const headers = ev.headers || {};
    const from = String(headers.from || headers.From || "unknown").trim();
    if (selfId && from === selfId) return null;
    const body = ev.body != null ? String(ev.body) : "";
    const path = typeof ev.path === "string" ? ev.path : "";
    // WIRE TRUTH, verified against the broker's own store on 2026-07-25 (do not
    // re-derive this by assumption; two prior patches got it wrong):
    //   - DELIVER frame headers carry `from` and `content-length`. Nothing else.
    //   - The NDJSON envelope carries a TOP-LEVEL `ts`.
    //   - That `ts` equals delivery_log.delivered_utc, NOT messages.created_utc.
    // So `ts` is when the broker handed the frame to this listener, which lags
    // the send whenever delivery is queued — 76s and 47s on the two frames
    // measured, and two messages from different seats flushed together share an
    // identical stamp. SEND-TIME IS NOT ON THE WIRE. It exists only server-side.
    // Label this what it is. A stamp labelled "sent" that holds arrival time is
    // worse than no stamp: it launders arrival time through the authority of a
    // machine timestamp, which is the exact error this render was added to stop.
    const pick = (o, keys) => {
        if (!o || typeof o !== "object") return "";
        for (const k of keys) {
            const v = o[k];
            if (typeof v === "string" && v.trim()) return v.trim();
            if (typeof v === "number" && Number.isFinite(v)) return new Date(v).toISOString();
        }
        return "";
    };
    const KEYS = ["ts", "Ts", "TS", "timestamp", "Timestamp", "time", "Time", "delivered_utc", "deliveredUtc"];
    const ts = pick(ev, KEYS) || pick(headers, KEYS);
    const sent = ts ? ` (received ${ts}; send-time not carried on the wire)` : "";

    if (path.includes("/channels/")) {
        const seg = path.split("/channels/")[1] || "";
        const channel = seg.split("/")[0];
        return {
            kind: "channel",
            from,
            channel,
            ts,
            prompt:
                `📢 [agent-broker] New message on channel #${channel} from ${from}${sent}:\n\n` +
                `${body}\n\n---\n` +
                `(This arrived via the agent-broker Monitor. Use the broker_broadcast tool to reply ` +
                `on the channel, or broker_send_dm to reply privately to ${from}.)`,
        };
    }

    return {
        kind: "dm",
        from,
        ts,
        prompt:
            `📨 [agent-broker] New direct message from ${from}${sent}:\n\n` +
            `${body}\n\n---\n` +
            `(This arrived via the agent-broker Monitor. To reply, call the broker_send_dm tool ` +
            `with to="${from}".)`,
    };
}

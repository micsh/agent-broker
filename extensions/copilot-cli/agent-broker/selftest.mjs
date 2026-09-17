#!/usr/bin/env node
/**
 * Self-test for the agent-broker binding's resume-banner identity guard and queue helpers.
 *
 * Why this file exists: the guard below is what stops one seat's resume banner
 * showing another seat's DMs (product@neon, 2026-08-27). Two of its properties are
 * invisible to ordinary review and are therefore pinned here:
 *
 *   1. REACHABILITY. After the recipient-path filter landed, the identity-mismatch
 *      refusal looks like dead code. It is not: findPriorOutput scans the WHOLE file
 *      for `"as":"<id>"`, while listenerIdentity reads only the FIRST one. A foreign
 *      listener that merely mentions this seat later in its output is still selected,
 *      and only the refusal catches it. Case 1 constructs exactly that asymmetry.
 *
 *   2. THE IDENTITY-ONLY BOUND. The refusal line may name seat identities and nothing
 *      else -- never a fact about the rejected listener's correspondence. Case 2 pins
 *      the line's shape and case 3 pins the material, so a well-meant
 *      "(3 messages skipped)" fails a test instead of shipping.
 *
 * SCOPE / BOUND (sightline@neon, 2026-08-27). This file is wired into the kit gate as a
 * required check, so its pass line is now quoted by readers who did not write it. The
 * count is derived from the cases that ran, never declared -- but a bare "N/N passed" on
 * a required check still reads as a completeness claim, and it is not one. What the cases
 * cover, and only this:
 *
 *   COVERED -- the resume-banner identity guard. Listener selection under the
 *   findPriorOutput/listenerIdentity asymmetry, and that the resulting refusal is not
 *   silent but announces itself on every resume (cases 1, 1b); the refusal line's shape
 *   and its identity-only material (cases 2-3, the latter looping over body/sender/seq/
 *   stamp, each planted token carrying its own control so a silent non-plant fails
 *   instead of passing); own-seat pass-through, i.e. that the guard does not refuse the
 *   seat it protects (cases 4-4b); and recipient filtering -- a DM addressed to another
 *   seat is dropped from the banner (case 5) while a self-addressed one survives
 *   (5-control, which is what stops case 5 passing by filtering everything). Queue coverage:
 *   broker-only classification and pending/steering counts (case 6); exact coalesced text,
 *   queue-head insertion, removal accounting, and non-broker preservation (cases 7-8);
 *   empty-broker behavior (case 9); resume RPC wiring (case 10); and tool-side RPC failure
 *   propagation (case 11).
 *
 *   NOT COVERED, and not claimed: anything outside the resume-banner path -- DM send,
 *   delivery, live queue scheduling, or broker-side ordering. The lifecycle cases run against
 *   a constructed fixture directory; queue cases run against an in-memory implementation of
 *   the SDK queue RPC contract. They pin the BEHAVIOUR OF THESE FUNCTIONS and say nothing
 *   about whether the bytes under test are the bytes in service; that is broker-parity's
 *   question, not this file's. Case 3 proves the planted tokens do not leak, which is narrower
 *   than "no foreign material can leak" -- it is a plant-tested floor, not a ceiling.
 *
 *   Green here therefore means the guard behaves as pinned, never that the binding is
 *   correct. A coverage claim states the scope it was measured over; this is that scope.
 *
 * Run: node selftest.mjs
 * Exit 0 = all cases pass. Exit 1 = a case failed. Exit 2 = the harness itself failed
 * to build, which is NOT a pass (a test that cannot run must not be silent).
 */

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- assertions
const results = [];
function check(name, pass, detail = "") {
    results.push({ name, pass, detail });
    console.log(`${pass ? "  ok  " : " FAIL "} ${name}${detail && !pass ? ` -- ${detail}` : ""}`);
}

// ---------------------------------------------------------------- harness
// The installed extension imports the SDK, which the host injects at runtime; the
// binding directory has no node_modules. Stub it, and re-export the internal we test.
let root;
let buildLifecycleSummary;
let brokerQueueStatus;
let coalesceBrokerQueue;
let resumeDecision;
let joinedOptions;
let queueState;
try {
    root = mkdtempSync(join(tmpdir(), "broker-selftest-"));
    const harness = join(root, "harness");
    const sdk = join(harness, "node_modules", "@github", "copilot-sdk");
    const outputs = join(root, "outputs");
    const fakeTemp = join(root, "temp");
    mkdirSync(sdk, { recursive: true });
    mkdirSync(outputs, { recursive: true });
    mkdirSync(join(fakeTemp, "claude"), { recursive: true });

    queueState = {
        items: [],
        steeringMessages: [],
        inserted: [],
        removed: [],
        drainPausedCalls: [],
        nextId: 1,
    };
    globalThis.__brokerQueueTestSession = {
        rpc: {
            queue: {
                pendingItems: async () => ({
                    items: queueState.items.map((item) => ({ ...item })),
                    steeringMessages: [...queueState.steeringMessages],
                }),
                insertAt: async ({ position, message }) => {
                    const id = `inserted-${queueState.nextId++}`;
                    const item = {
                        id,
                        kind: "message",
                        displayText: message.displayPrompt ?? message.prompt,
                        agentMode: message.agentMode ?? "interactive",
                    };
                    const clamped = Math.max(0, Math.min(position, queueState.items.length));
                    queueState.items.splice(clamped, 0, item);
                    queueState.inserted.push({ id, position, message: { ...message } });
                    return { id };
                },
                removeAt: async ({ id }) => {
                    const index = queueState.items.findIndex((item) => item.id === id);
                    if (index < 0) return { removed: false };
                    queueState.items.splice(index, 1);
                    queueState.removed.push(id);
                    return { removed: true };
                },
                setDrainPaused: async ({ paused }) => {
                    queueState.drainPausedCalls.push(paused);
                },
            },
        },
        log: async () => {},
    };
    writeFileSync(
        join(sdk, "package.json"),
        JSON.stringify({ name: "@github/copilot-sdk", type: "module", exports: { "./extension": "./extension.mjs" } }),
    );
    writeFileSync(
        join(sdk, "extension.mjs"),
        [
            "export function joinSession(options) {",
            "  globalThis.__brokerJoinedOptions = options;",
            "  return globalThis.__brokerQueueTestSession;",
            "}",
            "",
        ].join("\n"),
    );
    copyFileSync(join(HERE, "lib.mjs"), join(harness, "lib.mjs"));

    const src = readFileSync(join(HERE, "extension.mjs"), "utf8");
    writeFileSync(
        join(harness, "extension.mjs"),
        `${src}\nexport { buildLifecycleSummary, brokerQueueStatus, coalesceBrokerQueue, resumeDecision };\n`,
    );

    // CLAUDE_OUTPUT_DIR is join(tmpdir(), "claude"), read at module load -- redirect
    // TEMP so the test never touches a real seat's output directory.
    process.env.TEMP = fakeTemp;
    process.env.TMP = fakeTemp;
    process.env.COPILOT_BROKER_OUTPUT_DIR = outputs;

    // The module-load resume path must be a NO-OP under this harness (the stub session
    // has no sessionId, so authority is unverifiable) -- otherwise importing the module
    // in a test would spawn a real broker listener. COPILOT_BROKER_STATE_DIR is also
    // pointed into the sandbox so no real seat's saved state is ever readable here.
    process.env.COPILOT_BROKER_STATE_DIR = join(root, "state");
    ({ buildLifecycleSummary, brokerQueueStatus, coalesceBrokerQueue, resumeDecision } = await import(
        pathToFileURL(join(harness, "extension.mjs")).href
    ));
    joinedOptions = globalThis.__brokerJoinedOptions;
    globalThis.__outputs = outputs;
} catch (err) {
    console.error(`HARNESS FAILED TO BUILD: ${err && err.stack ? err.stack : err}`);
    console.error("This is not a pass. Exiting 2.");
    process.exit(2);
}

const OUT = globalThis.__outputs;
const SELF = "sightline@neon";
const FOREIGN = "product@neon";

// Planted tokens. Every one is a fact about the FOREIGN seat's correspondence and
// must never reach a banner rendered for SELF. Used to BUILD the fixture only.
const PLANT = {
    body: "PLANTED-BODY-cae21f-the-ledger-cite-arc",
    sender: "architect@neon",
    seq: "seq:1978",
    stamp: "2026-08-27T12:46:57Z",
};

// Independent spelling of the same tokens, used to CHECK the fixture. Deliberately not
// derived from PLANT: a single constant that both writes and checks cancels its own
// typo, so the control can never fail and the absence assertions below pass vacuously.
// Measured, not theorised -- with one constant, a mutation that misspelled the plant
// was NOT caught (2026-08-27). If these two ever disagree the control fails loudly,
// which is the intended behaviour, not drift to be tidied away.
const PLANT_EXPECTED = {
    body: "PLANTED-BODY-cae21f-the-ledger-cite-arc",
    sender: "architect@neon",
    seq: "seq:1978",
    stamp: "2026-08-27T12:46:57Z",
};

function writeOutput(name, lines) {
    const file = join(OUT, name);
    writeFileSync(file, lines.map((l) => (typeof l === "string" ? l : JSON.stringify(l))).join("\n") + "\n");
    return file;
}

// ---------------------------------------------------------------- case 1
// MUST-FIRE. Foreign listener whose FIRST "as" is product@neon, but which mentions
// sightline@neon later (a cached roster line). findPriorOutput selects it; only the
// identity check rejects it. If this stops firing, the guard has become unreachable
// and its removal would look safe.
writeOutput("foreign.output", [
    { as: FOREIGN, event: "connected", ts: PLANT.stamp, verb: "connect" },
    {
        as: FOREIGN,
        event: "deliver",
        path: `/agents/${FOREIGN}/dms`,
        headers: { from: PLANT.sender, seq: 1978 },
        body: `${PLANT.body} ${PLANT.seq}`,
        ts: PLANT.stamp,
    },
    { event: "roster", agents: [{ as: SELF }] },
]);

const foreignSummary = buildLifecycleSummary(SELF, null);
const refusalLine = foreignSummary.split("\n").find((l) => l.includes("REJECTED")) || "";

check("1. reachability: foreign listener is selected and REFUSED", refusalLine !== "", "no refusal line emitted");
check(
    "1b. refusal is not silent (it announces itself on every resume)",
    /REJECTED on identity mismatch/.test(refusalLine),
    refusalLine,
);

// ---------------------------------------------------------------- case 2
// SHAPE BOUND. Identities only, fixed wording, nothing appended. A maintainer adding
// "(3 messages skipped)" -- a measurement of another seat's activity -- fails here.
const SHAPE = /^\(prior listener REJECTED on identity mismatch: candidate \S+ announces \S+, not \S+\. No prior DMs shown\.\)$/;
check("2. refusal line matches the identity-only shape", SHAPE.test(refusalLine.trim()), refusalLine);

// ---------------------------------------------------------------- case 3
// NO-CORRESPONDENCE-LEAK, with its own control. Each token is first confirmed PRESENT
// in the fixture using the same containment probe, spelled independently of the
// constant that wrote it -- otherwise a misspelled plant makes every absence assertion
// below pass vacuously.
const fixtureText = readFileSync(join(OUT, "foreign.output"), "utf8");
for (const [label, token] of Object.entries(PLANT_EXPECTED)) {
    const controlHolds = fixtureText.includes(token);
    check(`3-control. planted ${label} really is in the fixture`, controlHolds, `token ${token} not planted`);
    if (!controlHolds) continue;
    check(`3. foreign ${label} does not reach the banner`, !foreignSummary.includes(token), `leaked: ${token}`);
}

// ---------------------------------------------------------------- case 4
// NEGATIVE CONTROL. Own listener resumes normally -- the guard must not refuse
// everything, which would pass cases 1-3 while breaking resume for every seat.
writeOutput("own.output", [
    { as: SELF, event: "connected", ts: PLANT.stamp, verb: "connect" },
    {
        as: SELF,
        event: "deliver",
        path: `/agents/${SELF}/dms`,
        headers: { from: "impl@neon" },
        body: "OWN-DM-visible-9a41c2",
        ts: PLANT.stamp,
    },
]);
rmSync(join(OUT, "foreign.output"));

const ownSummary = buildLifecycleSummary(SELF, null);
check("4. own listener is NOT refused", !ownSummary.includes("REJECTED"), ownSummary);
check("4b. own DM body is shown", ownSummary.includes("OWN-DM-visible-9a41c2"), ownSummary);

// ---------------------------------------------------------------- case 5
// THE ORIGINAL DEFECT. A DM addressed to another seat, sitting in this seat's own
// listener file, must not be rendered. extractLastDms once filtered on SENDER; the
// recipient is what the envelope actually carries.
writeOutput("own.output", [
    { as: SELF, event: "connected", ts: PLANT.stamp, verb: "connect" },
    {
        as: SELF,
        event: "deliver",
        path: `/agents/${FOREIGN}/dms`,
        headers: { from: PLANT.sender },
        body: "FOREIGN-ADDRESSED-b7d3e1",
        ts: PLANT.stamp,
    },
    {
        as: SELF,
        event: "deliver",
        path: `/agents/${SELF}/dms`,
        headers: { from: "impl@neon" },
        body: "SELF-ADDRESSED-4c8f0a",
        ts: PLANT.stamp,
    },
]);

const mixedSummary = buildLifecycleSummary(SELF, null);
check("5-control. self-addressed DM is shown", mixedSummary.includes("SELF-ADDRESSED-4c8f0a"), mixedSummary);
check(
    "5. DM addressed to another seat is filtered out",
    !mixedSummary.includes("FOREIGN-ADDRESSED-b7d3e1"),
    mixedSummary,
);

// ---------------------------------------------------------------- case 6
// Only queued message envelopes from the broker count. A command that merely contains
// the marker is a non-broker queue item and must survive coalescing.
const brokerA = {
    id: "broker-a",
    kind: "message",
    displayText: "📨 [agent-broker] New direct message from analyst@neon:\n\nalpha",
    agentMode: "interactive",
};
const ordinary = {
    id: "ordinary",
    kind: "message",
    displayText: "ordinary user prompt quoting [agent-broker] for debugging",
    agentMode: "interactive",
};
const markerCommand = {
    id: "marker-command",
    kind: "command",
    displayText: "/note [agent-broker]",
    agentMode: "interactive",
};
const brokerB = {
    id: "broker-b",
    kind: "message",
    displayText: "📨 [agent-broker] New direct message from impl@neon:\n\nbeta",
    agentMode: "interactive",
};
queueState.items = [brokerA, ordinary, markerCommand, brokerB];
queueState.steeringMessages = ["urgent steering message"];

const queueStatus = await brokerQueueStatus();
check(
    "6. queue status classifies broker messages only",
    queueStatus.brokerItems.map((item) => item.id).join(",") === "broker-a,broker-b" &&
        queueStatus.summary ===
            "broker queue: 2 broker message(s) among 4 pending item(s); 1 immediate steering message(s).",
    `ids=${queueStatus.brokerItems.map((item) => item.id).join(",")} summary=${queueStatus.summary}`,
);

// ---------------------------------------------------------------- cases 7-8
const expectedPrompt = `${brokerA.displayText}\n\n---\n\n${brokerB.displayText}`;
const coalesced = await coalesceBrokerQueue();
check(
    "7. coalescing preserves exact broker text and removes originals",
    queueState.inserted.length === 1 &&
        queueState.inserted[0].position === 0 &&
        queueState.inserted[0].message.prompt === expectedPrompt &&
        queueState.removed.join(",") === "broker-a,broker-b" &&
        coalesced.includes("Coalesced 2/2 broker message(s) into queue item inserted-1."),
    `inserted=${JSON.stringify(queueState.inserted)} removed=${queueState.removed.join(",")} result=${coalesced}`,
);
check(
    "8. coalescing preserves non-broker entries and queue-head placement",
    queueState.items.map((item) => item.id).join(",") === "inserted-1,ordinary,marker-command" &&
        queueState.items[1].displayText === ordinary.displayText &&
        queueState.items[2].displayText === markerCommand.displayText,
    `queue=${JSON.stringify(queueState.items)}`,
);

// ---------------------------------------------------------------- case 9
queueState.items = [ordinary, markerCommand];
queueState.steeringMessages = [];
queueState.inserted = [];
queueState.removed = [];
const emptyResult = await coalesceBrokerQueue();
check(
    "9. coalescing is inert without broker messages",
    queueState.items.map((item) => item.id).join(",") === "ordinary,marker-command" &&
        queueState.inserted.length === 0 &&
        queueState.removed.length === 0 &&
        emptyResult.endsWith("Nothing addressable to coalesce."),
    `queue=${JSON.stringify(queueState.items)} result=${emptyResult}`,
);

// ---------------------------------------------------------------- case 10
const queueTool = joinedOptions?.tools?.find((tool) => tool.name === "broker_queue");
check("10-control. broker_queue tool is registered", Boolean(queueTool), "tool registration missing");
queueState.drainPausedCalls = [];
const resumeResult = queueTool ? await queueTool.handler({ operation: "resume" }) : "";
check(
    "10. broker_queue resume releases the drain pause",
    queueState.drainPausedCalls.join(",") === "false" && resumeResult.startsWith("Queue drain resumed."),
    `calls=${queueState.drainPausedCalls.join(",")} result=${resumeResult}`,
);

// ---------------------------------------------------------------- case 11
// Tool calls surface RPC failures. The slash command logs them for an interactive user,
// but a tool must not return success-shaped text when the queue API is unavailable.
const pendingItems = globalThis.__brokerQueueTestSession.rpc.queue.pendingItems;
globalThis.__brokerQueueTestSession.rpc.queue.pendingItems = async () => {
    throw new Error("fixture queue unavailable");
};
let propagated = "";
try {
    if (queueTool) await queueTool.handler({ operation: "status" });
} catch (error) {
    propagated = error.message;
} finally {
    globalThis.__brokerQueueTestSession.rpc.queue.pendingItems = pendingItems;
}
check(
    "11. broker_queue tool propagates queue RPC failures",
    propagated === "fixture queue unavailable",
    `error=${JSON.stringify(propagated)}`,
);

// ---------------------------------------------------------------- case 12
// RESUME-ON-RESPAWN decision layer (host-recycle cure, 2026-09-17). The authority rule
// pinned: resume ONLY a same-session explicit connect. These cells test the PURE
// decision function; the spawn path is startMonitor, exercised live. Coverage bound,
// stated: green here pins the decision, not the reconnect's transport.
const SID = "session-abc-123";
const OTHER_SID = "session-zzz-999";
const goodState = (over = {}) =>
    JSON.stringify({ identity: "sightline@neon", sessionId: SID, options: { noLoop: true, announce: "architect@neon" }, updatedAt: "2026-09-17T05:00:00Z", ...over });

const d0 = resumeDecision(null, SID);
check("12-control. no saved state -> fresh (pre-cure behaviour unchanged)", d0.action === "fresh", JSON.stringify(d0));

const dNoSid = resumeDecision(goodState(), "");
check("12a. missing session id -> fresh, NEVER resume (authority unverifiable)", dNoSid.action === "fresh", JSON.stringify(dNoSid));

const dSame = resumeDecision(goodState(), SID);
check(
    "12b. same-session state -> resume with the saved identity",
    dSame.action === "resume" && dSame.identity === "sightline@neon",
    JSON.stringify(dSame),
);
check(
    "12b-2. resume strips announce (a recycle must not re-spam a peer) and keeps other options",
    dSame.action === "resume" && dSame.options.announce === "" && dSame.options.noLoop === true,
    JSON.stringify(dSame.options),
);

const dForeign = resumeDecision(goodState({ sessionId: OTHER_SID }), SID);
check(
    "12c. foreign-session state -> REFUSED (the cure creates no cross-session surface)",
    dForeign.action === "refuse" && dForeign.reason.includes(OTHER_SID) && dForeign.reason.includes(SID),
    JSON.stringify(dForeign),
);

const dCorrupt = resumeDecision("{not json", SID);
check("12d. corrupt state -> typed refusal, never a silent connect", dCorrupt.action === "refuse", JSON.stringify(dCorrupt));

const dNoId = resumeDecision(JSON.stringify({ sessionId: SID }), SID);
check("12e. identity-less state -> typed refusal", dNoId.action === "refuse", JSON.stringify(dNoId));

// ---------------------------------------------------------------- report
rmSync(root, { recursive: true, force: true });
delete globalThis.__brokerJoinedOptions;
delete globalThis.__brokerQueueTestSession;
const failed = results.filter((r) => !r.pass);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length ? 1 : 0);

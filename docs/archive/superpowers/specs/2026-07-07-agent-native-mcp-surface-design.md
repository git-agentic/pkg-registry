# Phase 11 — Agent-Native MCP Surface (Sentinel as a tool coding agents consult before installing)

**Date:** 2026-07-07
**Status:** Approved design, pre-implementation
**Extends:** ADR-0001 (proxy wedge — the MCP server is a client of it), ADR-0007
(client integration), ADR-0013 (approval gate — the request path preserves its
fail-closed posture), ADR-0002 (deterministic scoring — the MCP layer does no
scoring). Supersedes nothing.

## Problem

Sentinel is "an agent-auditable security layer for npm," but after ten phases it
has no agent-native interface. An agent that wants a verdict before running
`npm install` must shell out to the `sentinel` CLI or hit raw `/-/*` HTTP endpoints.
Ten phases produced signal an agent cannot cleanly reach: the 0–100 score and
findings, the capability manifest, signature + Sigstore-verified provenance identity,
the whole-tree gate, and live runtime-violation/quarantine state.

Phase 11 ships the thesis: a Model Context Protocol server exposing Sentinel's
decision-support surface as native tools, so a coding agent (Claude Code/Desktop,
Cursor, etc.) consults Sentinel **before** it installs — and can *request* an
approval without being able to *grant* one.

## Decisions (brainstorm outcomes)

1. **Thin client to the running proxy**, not an embedded-core reimplementation and
   not a proxy-or-embed hybrid. Every tool maps to an existing `/-/*` endpoint, so an
   agent's verdict is byte-identical to what a real install hits — the loaded signed
   policy, integrity cache, private namespaces, provenance trust wiring, and live
   quarantine state are all reused, never reimplemented. Rejected: embed-core (loses
   policy/private/provenance/violations → a *different* verdict than a real install,
   dangerous for a decision tool) and hybrid (a silent offline fallback could report
   a blocked package as allow).
2. **Read-only tools + one `request_approval` write path.** The five read tools are
   freely exposed; the sole write tool records a *pending request* a human resolves —
   it never auto-approves. Rejected: read-only-only (no in-band way for the agent to
   signal "I need this," breaking the consult→proceed loop) and full read+write
   (letting the agent approve/clear-quarantine defeats the gate it is guarded by, and
   the endpoints are unauthenticated today).
3. **New `packages/mcp` workspace**, official `@modelcontextprotocol/sdk`, **stdio**
   transport (the standard for local coding-agent hosts). The SDK is a dependency of
   this package only.

## Section 1 — Architecture & data flow

A new `packages/mcp` workspace. The agent host launches `node packages/mcp/dist/index.js`;
the server registers tools and connects a stdio transport. It is a thin HTTP client to
a Sentinel proxy at `SENTINEL_PROXY` (default `http://localhost:4873`).

Files (small, single-responsibility):
- `src/index.ts` — bootstrap: build the client from env, register tools, connect
  `StdioServerTransport`.
- `src/client.ts` — `ProxyClient`: one typed `fetch` wrapper over the `/-/*`
  endpoints. A proxy-unreachable / non-OK response throws a `ProxyError` carrying the
  cause; it is never swallowed into a fabricated verdict.
- `src/tools.ts` — each tool as `{ name, description, inputSchema, handler }` where
  `handler(args, client)` is a pure async function returning
  `{ text: string; structured: object }`. Pure over the client ⇒ unit-testable with
  no transport.
- `src/format.ts` — renders each verdict to concise agent-readable text.

The server wraps each handler: validate input against the schema, call the handler,
return `{ content: [{ type: "text", text }], structuredContent: structured }`; on a
`ProxyError` or validation failure, return an MCP tool error naming the cause.

## Section 2 — The read tools

Every tool returns a text summary (for the agent to reason over) plus a
`structuredContent` JSON block. All read-only; all fail explicitly on a proxy error
(unreachable, 404 unknown package) rather than synthesizing a verdict.

- **`sentinel_audit`** — input `{ package: string, version?: string }` (version
  defaults to the packument's latest). Calls `GET /-/audit/:pkg/:version`. Returns
  `verdict` (allow|warn|block), `score`, top findings (ruleId/severity/message), the
  capability list, `signature` + `provenance` status (with verified build identity if
  present), `hasInstallScripts`, and **`quarantined`** — whether this integrity has a
  recorded runtime violation (projected from `GET /-/violations`, since a quarantine is
  a serve-time overlay not baked into the cached report). The core "should I install
  this?" tool.
- **`sentinel_audit_tree`** — input `{ lockfile: string }` (path to a
  `package-lock.json`). Reuses the CLI's `parseLockfile(raw, { omitDev })` →
  `Coordinate[]` to build the list, then `POST /-/audit-tree`. Returns the aggregate
  verdict, `gated`, the per-status counts, and the worst rows. "Is this whole project
  safe to install?"
- **`sentinel_capabilities`** — input `{ package, version? }`. Calls
  `GET /-/manifest/:pkg/:version`. Returns the capability manifest (kind+target), the
  capability delta vs the prior version, and the approval state
  (approved|inherited|required|denied|n-a). "What can it do, and is it approved?"
- **`sentinel_check_provenance`** — input `{ package, version? }`. Projects the audit
  report's provenance: status (`verified|invalid|absent|unknown`) and, when verified,
  the build identity (source repo, workflow, builder, commit). "Who built this and is
  it cryptographically proven?"
- **`sentinel_list_violations`** — input `{ package?: string }` (optional filter).
  Calls `GET /-/violations`. Returns recorded runtime violations and which integrities
  are quarantined. "What has been caught misbehaving?"

## Section 3 — `request_approval` + pending-request store + dashboard

Privilege boundary: the agent may *ask*, not *grant*. `sentinel_request_approval` does
**not** call `POST /-/approvals` (an actual decision); it records a distinct pending
request a human resolves.

- **New proxy store `ApprovalRequestStore`** (`packages/proxy/src/approval-requests.ts`)
  — integrity-keyed, in-memory + optional JSON file, mirroring `ApprovalStore`/
  `ViolationStore`. Record shape:
  `{ name, version, integrity, reason, requestedBy: { type, id }, capabilities: Capability[], requestedAt }`.
- **New endpoints**: `POST /-/approval-requests` — body
  `{ name, version, integrity, reason, requestedBy? }`; requires an existing audited
  report for the integrity (else 400, "audit first"), snapshots the report's
  capabilities, records the request. `GET /-/approval-requests` — lists pending
  requests. A request is auto-dropped once a matching approval **decision** for that
  integrity lands (checked in the existing `POST /-/approvals` handler:
  `approvalRequests.clear(integrity)` after recording the decision).
- **`sentinel_request_approval`** MCP tool — input `{ package, version?, reason: string }`.
  Resolves the integrity via the audit endpoint, POSTs the request with
  `requestedBy` defaulting to `{ type: "agent", id: "mcp" }` (the existing `actor`
  shape), returns confirmation that a human must resolve it. It surfaces the current
  verdict too, so the agent knows what it is asking to override.
- **Dashboard**: a "Pending approval requests" panel (sibling of Approvals/Violations)
  showing package, requester, reason, and the capabilities at stake, with
  **Approve / Deny** buttons that call the existing `POST /-/approvals`. This closes
  the loop in-band — agent requests → human sees it → approves → next install proceeds
  — while the gate stays un-openable by the agent (fail-closed, ADR-0013 preserved).

## Section 4 — Config, error handling, testing, DoD

*Config:* `SENTINEL_PROXY` (default `http://localhost:4873`). README shows the
agent-host config block (`command: "node"`, `args: ["packages/mcp/dist/index.js"]`,
`env: { SENTINEL_PROXY }`) for Claude Code/Desktop and Cursor. No auth this phase —
the read tools are safe and the one write path only *requests*; the ADR names
authenticating the MCP↔proxy hop as the follow-on once the API-auth phase lands.

*Error handling:* a `ProxyError` (connection refused, non-OK status, 404 unknown
package, 400 audit-first) becomes an explicit MCP tool error naming the cause — never
a fabricated allow/block. A malformed tool input is rejected by schema validation with
a clear message; the server never crashes on bad input.

*Testing (hermetic):* handlers are pure over the client, so most tests drive them
directly against an **in-process proxy** (`LocalFixtureUpstream` + `createServer`, the
existing pattern) and assert real verdicts on existing fixtures — `color-stream@1.4.1`
→ block, `leftpad-lite@1.0.0` → allow, and a quarantined integrity (POST a violation
first) → `sentinel_audit` reports `quarantined: true`. One **end-to-end** test wires the
MCP SDK's in-memory linked transport (client↔server) to prove tools register and
round-trip. `sentinel_request_approval` → asserts `GET /-/approval-requests` returns the
pending request, and a subsequent `POST /-/approvals` for that integrity clears it. A
proxy-unreachable test asserts the tool returns an error, not a verdict. No new
fixtures. Invariant #1 untouched — the MCP layer does no scoring (pure pass-through).

*Definition of done:* `npm run build` clean (the new `packages/mcp` is added to the
project references — core → mcp, mirroring proxy/cli); `npm test` green (new count
recorded in CLAUDE.md, darwin-skip caveats preserved); the malicious fixture still
blocks through both the proxy and the `sentinel_audit` tool; ADR-0024 recorded;
ARCHITECTURE.md extended (§4 client-integration section gains the MCP surface; §5 store
list gains `ApprovalRequestStore`); CLAUDE.md phase summary + count; README MCP setup +
tool list.

## Out of scope (deferred beyond Phase 11)

- Authenticating the MCP↔proxy hop and the `/-/approval-requests` endpoint (part of the
  deferred API-auth phase; the write path only *requests*, so the trusted-deployment
  posture holds for now).
- Auto-approve / clear-quarantine MCP tools (deliberately never — the agent must not be
  able to open the gate it is guarded by).
- HTTP/SSE transport, remote/multi-tenant MCP hosting (stdio local integration only).
- An `install` tool that runs npm (Sentinel attaches signal; it does not drive installs
  — ADR-0001 wedge posture).
- Embedding the audit engine for offline/no-proxy operation (rejected in §Decisions).

## Invariants preserved

1. **Deterministic score** — the MCP layer does no scoring; it relays the proxy's
   verdict verbatim.
2. **LLM never scores** — untouched.
3. **Sync gate cheap** — MCP tools are out-of-band decision support; nothing added to
   the install request path.
4. **Cache key = integrity** — verdicts and the approval-request/quarantine projections
   are integrity-keyed, reusing the proxy's stores.
5. **Proxy transparency** — the MCP server is a read/request client; it does not alter
   packument passthrough.
6. **Fail-open rules / never crash** — the MCP server fails explicitly on a proxy error
   and never fabricates a verdict; a bad tool input is rejected, not crashed on.
7. **Private namespaces authoritative** — the audit/capabilities tools reflect the
   proxy's private-store verdicts unchanged.
8. **Approval gate fail-closed (ADR-0013)** — the agent can request but not grant; only
   a human (later, an authenticated role) decides.

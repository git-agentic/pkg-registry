# ADR-0024: Agent-native MCP surface (thin stdio client, request-not-grant)

**Status:** Accepted (Phase 11)
**Date:** 2026-07-07

## Context

Sentinel has called itself an "agent-auditable security layer" since Phase 1,
but for ten phases the only way an agent could reach it was by shelling out to
the `sentinel` CLI and parsing text/JSON output — a workable but informal
interface, with no discoverable tool schema and no standard transport. The
Model Context Protocol (MCP) is the emerging standard for exposing exactly
this kind of tool surface to agent hosts (Claude Code, Claude Desktop, and
others) without each host needing bespoke CLI-wrapping glue. Phase 11 gives
Sentinel a first-class MCP server so an agent can call `sentinel_audit`, get a
structured verdict, and decide whether to install — the same wedge as the CLI,
on the transport agents already speak.

## Decision

- **A thin stdio MCP client, not an embedded engine.** `packages/mcp` is a new
  workspace: `createMcpServer(client)` (`packages/mcp/src/index.ts`) builds an
  `McpServer` (`@modelcontextprotocol/sdk`) and registers every tool against a
  `ProxyClient`. `main()` constructs the client from `SENTINEL_PROXY` (default
  `http://localhost:4873`), connects a `StdioServerTransport`, and runs only
  when invoked as the entrypoint (the same `realpathSync` guard hardened for
  `sentinel-script-shell` in Phase 6, so importing `index.js` from a test never
  triggers `main()`). The package ships as `bin: sentinel-mcp`.
- **`ProxyClient` (`packages/mcp/src/client.ts`) does no scoring of its own.**
  It is a fetch wrapper over the proxy's existing `/-/audit`, `/-/manifest`,
  `/-/audit-tree`, `/-/violations`, and `/-/approval-requests` endpoints.
  Every method returns parsed JSON from the proxy or throws `ProxyError` —
  never a fabricated verdict. `audit`/`manifest` resolve `latest` from the
  packument's `dist-tags` when a version is omitted, matching CLI/dashboard
  behavior elsewhere in the codebase.
- **Six tools** (`packages/mcp/src/tools.ts`), five read-only and one
  write-a-request:
  - `sentinel_audit` — verdict/score/findings/capabilities/signature/
    provenance for a package version, plus `quarantined`, which is **projected
    from `/-/violations`** rather than read off the cached report — quarantine
    is a Phase 10 serve-time overlay (ADR-0023), not a field ever written into
    `AuditReport`, so the tool has to ask the same way the tarball serve gate
    does.
  - `sentinel_audit_tree` — parses a `package-lock.json` via `parseLockfile`
    (moved to `@sentinel/core` this phase, see below) and calls
    `POST /-/audit-tree` for the aggregate.
  - `sentinel_capabilities` — the capability manifest, delta vs. the prior
    version, and approval state, from `/-/manifest`.
  - `sentinel_check_provenance` — provenance status and, when verified, the
    attested build identity (workflow/issuer/repo/ref/builder/commit).
  - `sentinel_list_violations` — recorded runtime violations and which builds
    are quarantined, from `/-/violations`.
  - `sentinel_request_approval` — the one write tool: `POST
    /-/approval-requests` to record a **pending** request. It never approves.
- **New `ApprovalRequestStore` + `/-/approval-requests` in the proxy.**
  `packages/proxy/src/approval-requests.ts` mirrors the existing
  `ApprovalStore`/`ViolationStore` shape: integrity-keyed, in-memory with an
  optional `SENTINEL_APPROVAL_REQUESTS` JSON-file persistence. `POST
  /-/approval-requests` 400s unless the integrity already has an audited
  report (the same anti-spoofing bound ADR-0023 established for
  `/-/violations` — a request can only target a real, already-audited
  tarball). A subsequent human decision through the existing `POST
  /-/approvals` endpoint auto-clears the matching pending request
  (`approvalRequests.clear(d.integrity)`), and the dashboard grew a "Pending
  approval requests" panel with Approve/Deny actions so a human has somewhere
  to act on what the agent asked for.
- **`parseLockfile`/`Coordinate` moved from `@sentinel/cli` to
  `@sentinel/core`.** Both the CLI's `audit-tree` command and the MCP's
  `sentinel_audit_tree` tool need the same lockfile parser; importing it from
  `cli` would pull in `cli`'s own `argv[1]`-based entrypoint guard, which would
  misfire when `mcp`'s `index.js` is the actual process entrypoint. Hoisting
  the parser to `core` (which both packages already depend on) sidesteps that
  footgun entirely rather than working around it.
- **Input validation is the MCP SDK's, not hand-rolled.** Each tool declares a
  `zod` `inputSchema`; a malformed call is rejected by the SDK before the
  handler runs and returns `isError: true` with a text explanation — not a
  thrown exception that could crash the server or, worse, get swallowed into a
  fabricated success.

## Privilege boundary

**The agent can request; only a human can grant.** `sentinel_request_approval`
records a `PENDING` entry in `ApprovalRequestStore` — full stop. There is no
`sentinel_approve` tool, no auto-approve path, and no
clear-quarantine-from-MCP tool, and none of these will be added silently in a
later phase without a fresh ADR: the entire point of Phase 11 is to give an
agent eyes (six ways to read the current risk posture) without giving it hands
on the gate. `POST /-/approvals` — the endpoint that actually grants or
revokes approval — is untouched by this phase and remains reachable only
through the dashboard/CLI paths a human drives. ADR-0013's fail-closed
approval-gate contract (unapproved capability ⇒ denied) is preserved exactly;
Phase 11 adds a way to *ask* for a capability to be approved, not a way to
grant one.

## Auth posture

There is no MCP↔proxy authentication this phase. `ProxyClient` talks to
`SENTINEL_PROXY` over plain HTTP with no credential, the same unauthenticated
posture `/-/approvals` and `/-/violations` have had since ADR-0011/0013 and
ADR-0023 respectively — there is still no per-tenant identity model to
authenticate against anywhere in the proxy. This is deliberately narrower risk
than it might look: the write path this phase adds (`/-/approval-requests`)
only *requests*, gated by the same "must already have an audited report"
bound ADR-0023 established, and the actual grant path (`/-/approvals`) is
unchanged. Authenticating the MCP↔proxy hop — so a `sentinel_request_approval`
call is attributable to a specific agent identity rather than the
`requestedBy: { type: "agent", id: "mcp" }` default — is explicitly the
follow-on with the broader API-auth phase, not something this ADR claims to
have solved.

## Consequences

- **The verdict an agent sees is byte-identical to what a real install would
  see**, because `ProxyClient` calls the same `/-/audit`/`/-/manifest`
  endpoints the CLI and the tarball serve gate use — there is no second code
  path that could drift from the one that actually gates installs.
- **The MCP layer does zero scoring.** No rule runs in `packages/mcp`; every
  tool is a fetch-and-format over data the proxy already produced. Invariant
  #1 (scoring is deterministic given a policy) is untouched by this phase —
  there was never a second place a score could be computed.
- **A proxy error fails explicitly, never as a fabricated verdict.** An
  unreachable proxy, a non-OK response, or a malformed body all throw
  `ProxyError`, which `createMcpServer`'s handler wrapper turns into
  `isError: true` with the error text — an agent that can't reach the proxy
  gets a visible failure, never a default-allow (or default-block) guess
  standing in for a real audit.
- Every read tool now has a text summary *and* a `structuredContent` payload
  (`packages/mcp/src/tools.ts`), so an agent host can render the text for a
  human-in-the-loop transcript while another automated caller consumes the
  structured fields directly.

## Deferred

- **MCP↔proxy authentication** — the follow-on API-auth phase; today any
  process that can reach `SENTINEL_PROXY` can call every tool, including
  `sentinel_request_approval`.
- **HTTP/SSE transport and remote hosting** — the server is stdio-only,
  spawned locally by the agent host; a remotely hosted MCP server serving
  multiple agents is out of scope for this phase.
- **An install tool.** Deliberately not built: every tool this phase ships is
  either read-only or request-only. An MCP tool that actually runs `npm
  install` (even routed through the proxy) is a materially different trust
  decision than "show me the verdict" or "ask a human," and is left for a
  future ADR to weigh on its own.
- **An embedded-core offline mode**, so the server could still answer basic
  questions with the proxy down — rejected below, not merely postponed for
  convenience.

## Rejected

- **Embed `@sentinel/core` directly in the MCP server (score locally, no
  proxy round-trip)** — rejected: the whole point of "byte-identical to a
  real install" is that both paths run through the *same* audit
  (`/-/audit`), cached by the *same* integrity key, gated by the *same*
  `EnterprisePolicy`. An embedded copy of `core` in the MCP process would need
  its own policy load, its own `AuditStore`/cache, and could silently drift
  from what the proxy actually enforces — a different verdict than the one a
  real install would see, exactly the failure mode this ADR's Consequences
  section rules out.
- **A hybrid: try the proxy, fall back to an embedded local audit if
  unreachable** — rejected outright: a silent offline fallback is worse than
  an explicit failure, because it can report `allow` for a package the
  fleet's real policy (private namespaces, per-enterprise `deny`/`allow`
  rules, signed policy hash) would have blocked, with no visible signal to
  the agent or the human reading its output that the answer came from a
  degraded, unauthoritative path. `ProxyError` on an unreachable proxy is the
  correct behavior precisely because it can't be mistaken for a real verdict.

Extends ADR-0001 (proxy wedge — the MCP server is another thin client to the
same proxy, not a second audit path), ADR-0007 (client integration — MCP joins
`sentinel audit`/`install`/`npx` as a fourth non-invasive integration mode),
ADR-0013 (approval gate fail-closed — `request_approval` can only ever ask,
never grant, preserving the fail-closed contract exactly), and ADR-0002
(deterministic scoring — invariant #1, which this phase touches nowhere).
Supersedes nothing.

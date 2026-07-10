# Phase 11 — Agent-Native MCP Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stdio MCP server (`packages/mcp`) exposing Sentinel's decision-support surface as native tools, backed by a running proxy, so a coding agent consults Sentinel before installing — read-only tools plus one `request_approval` that a human resolves.

**Architecture:** A new `packages/mcp` workspace using `@modelcontextprotocol/sdk`. It is a thin HTTP client to the proxy's existing `/-/*` endpoints; tool handlers are pure async functions over a `ProxyClient` (unit-testable without a transport). A new proxy `ApprovalRequestStore` + `/-/approval-requests` endpoints and a dashboard panel let an agent *request* an approval a human grants. `parseLockfile` moves to `@sentinel/core` so both cli and mcp consume it without coupling.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; new deps `@modelcontextprotocol/sdk@^1.29.0` + `zod` (in `packages/mcp` only).

## Global Constraints

- **Thin client, never reimplement:** every tool maps to an existing `/-/*` endpoint; the verdict must be what a real install hits. No embedded-core auditing, no offline fallback.
- **Privilege boundary (ADR-0013 fail-closed):** the MCP server never grants approvals or clears quarantines. `sentinel_request_approval` records a *pending request* only; it must NOT call `POST /-/approvals`.
- **Fail explicitly, never fabricate:** a proxy-unreachable / non-OK response becomes an MCP tool error naming the cause — never a synthesized allow/block.
- **Invariant #1 (deterministic score):** the MCP layer does zero scoring; it relays the proxy's verdict verbatim. The determinism test stays green.
- **Quarantine is a serve-time overlay (Phase 10), NOT in the cached `/-/audit` report** — `sentinel_audit` must project `quarantined` by consulting `GET /-/violations` and checking for a `quarantined` record on that integrity.
- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts`.
- Tests hermetic: in-process proxy (`LocalFixtureUpstream` + `createServer`) + the SDK's `InMemoryTransport`; never hit live npm in `npm test`.
- MCP SDK API (probed 2026-07-07): `new McpServer({name,version})`; `server.registerTool(name, { description, inputSchema: <zod raw shape> }, handler)`; handler returns `{ content: [{type:"text", text}], structuredContent }`; `InMemoryTransport.createLinkedPair()` → `[clientTransport, serverTransport]`; the SDK auto-validates inputs against the zod shape and returns `isError` on a bad input (no hand-rolled validation needed).
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.
- Every `createServer(...)` call gained a required `violations` field in Phase 10; the new `/-/approval-requests` work adds a required `approvalRequests` field — update EVERY call site (tests, `index.ts`, `scripts/demo.ts`).

---

### Task 1: Move `parseLockfile` to `@sentinel/core`

**Files:**
- Create: `packages/core/src/lockfile.ts` (moved from cli)
- Modify: `packages/core/src/index.ts` (export)
- Modify: `packages/cli/src/index.ts` (import from core)
- Delete: `packages/cli/src/lockfile.ts`
- Move: `packages/cli/test/lockfile.test.ts` → `packages/core/test/lockfile.test.ts` (repoint import)

**Interfaces:**
- Produces (used by Task 6): `parseLockfile(raw: string, opts?: { omitDev?: boolean }): Coordinate[]` and `interface Coordinate { name: string; version: string; integrity?: string }`, exported from `@sentinel/core`.

- [ ] **Step 1: Copy the file into core** — `git mv packages/cli/src/lockfile.ts packages/core/src/lockfile.ts`. It has no cli-specific imports (verify: it imports nothing from cli), so it compiles under core unchanged.

- [ ] **Step 2: Export from core** — append to `packages/core/src/index.ts`:

```ts
export { parseLockfile, type Coordinate } from "./lockfile.js";
```

- [ ] **Step 3: Repoint the cli consumer** — in `packages/cli/src/index.ts`, change the lockfile import from the local `./lockfile.js` to `@sentinel/core`. Find the existing `import { parseLockfile ... } from "./lockfile.js";` and replace its source with `"@sentinel/core"` (merge into the existing core import if there is one; keep `type Coordinate` if used).

- [ ] **Step 4: Move the test** — `git mv packages/cli/test/lockfile.test.ts packages/core/test/lockfile.test.ts` and repoint its import of the parser from `../src/lockfile.js` (unchanged relative path — same depth) . Verify the import line resolves; the test body is behavior-identical.

- [ ] **Step 5: Build + run the moved test + cli**

```bash
npm run build
npx tsx --test packages/core/test/lockfile.test.ts
npx tsx --test packages/cli/test/audit-tree*.test.ts 2>/dev/null || true
npm test 2>&1 | tail -4
```

Expected: build clean; lockfile test PASS; full suite green (the move is behavior-preserving — cli's audit-tree path still parses lockfiles, now via core).

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/lockfile.ts packages/core/src/index.ts packages/core/test/lockfile.test.ts packages/cli/src/index.ts
git add -u packages/cli/src/lockfile.ts packages/cli/test/lockfile.test.ts
git commit -m "refactor(phase11): move parseLockfile to @sentinel/core (shared by cli + mcp)"
```

---

### Task 2: `ApprovalRequestStore` (proxy)

**Files:**
- Create: `packages/proxy/src/approval-requests.ts`
- Test: `packages/proxy/test/approval-requests-store.test.ts`

**Interfaces:**
- Consumes: `Capability` from `@sentinel/core`.
- Produces (used by Task 3): `interface ApprovalRequest { name; version; integrity; reason; requestedBy: { type: "human"|"agent"; id: string }; capabilities: Capability[]; requestedAt: string }`; `class ApprovalRequestStore` with `record(r: Omit<ApprovalRequest,"requestedAt">, now?): ApprovalRequest`, `get(integrity)`, `clear(integrity): boolean`, `recent(limit?): ApprovalRequest[]`.

- [ ] **Step 1: Write the failing test** (`packages/proxy/test/approval-requests-store.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const base = {
  name: "left-pad", version: "1.3.0", integrity: "sha512-AAA",
  reason: "needed for string padding", requestedBy: { type: "agent" as const, id: "mcp" },
  capabilities: [{ kind: "network" as const, target: "*", evidence: [] }],
};

describe("ApprovalRequestStore", () => {
  test("records a pending request, retrievable by integrity", () => {
    const s = new ApprovalRequestStore();
    const rec = s.record(base, "2026-07-07T00:00:00Z");
    assert.equal(rec.requestedAt, "2026-07-07T00:00:00Z");
    assert.equal(s.get("sha512-AAA")?.reason, "needed for string padding");
    assert.equal(s.recent().length, 1);
  });

  test("re-recording the same integrity replaces (no duplicate)", () => {
    const s = new ApprovalRequestStore();
    s.record(base);
    s.record({ ...base, reason: "updated reason" });
    assert.equal(s.recent().length, 1);
    assert.equal(s.get("sha512-AAA")?.reason, "updated reason");
  });

  test("clear removes the request", () => {
    const s = new ApprovalRequestStore();
    s.record(base);
    assert.equal(s.clear("sha512-AAA"), true);
    assert.equal(s.get("sha512-AAA"), undefined);
    assert.equal(s.clear("sha512-AAA"), false);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/approval-requests-store.test.ts
```

Expected: FAIL — cannot find module `../src/approval-requests.js`.

- [ ] **Step 3: Implement `packages/proxy/src/approval-requests.ts`** (mirror `ViolationStore`)

```ts
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { Capability } from "@sentinel/core";

export interface ApprovalRequest {
  name: string;
  version: string;
  integrity: string;
  reason: string;
  requestedBy: { type: "human" | "agent"; id: string };
  capabilities: Capability[];
  requestedAt: string; // ISO-8601
}

/** Pending approval requests (an agent asks; a human grants). Integrity-keyed;
 *  mirrors ApprovalStore/ViolationStore (in-memory + optional JSON file). */
export class ApprovalRequestStore {
  private byIntegrity = new Map<string, ApprovalRequest>();
  private order: string[] = [];

  constructor(private readonly file?: string) {
    if (file && existsSync(file)) {
      try {
        for (const r of JSON.parse(readFileSync(file, "utf8")) as ApprovalRequest[]) this.index(r);
      } catch {
        /* start empty on a corrupt log */
      }
    }
  }

  record(r: Omit<ApprovalRequest, "requestedAt">, now = new Date().toISOString()): ApprovalRequest {
    const rec: ApprovalRequest = { ...r, requestedAt: now };
    this.index(rec);
    this.persist();
    return rec;
  }

  get(integrity: string | null | undefined): ApprovalRequest | undefined {
    return integrity ? this.byIntegrity.get(integrity) : undefined;
  }

  clear(integrity: string): boolean {
    const had = this.byIntegrity.delete(integrity);
    if (had) {
      this.order = this.order.filter((k) => k !== integrity);
      this.persist();
    }
    return had;
  }

  recent(limit = 50): ApprovalRequest[] {
    return this.order.slice(-limit).reverse()
      .map((k) => this.byIntegrity.get(k))
      .filter((x): x is ApprovalRequest => Boolean(x));
  }

  private index(r: ApprovalRequest): void {
    if (!this.byIntegrity.has(r.integrity)) this.order.push(r.integrity);
    this.byIntegrity.set(r.integrity, r);
  }

  private persist(): void {
    if (!this.file) return;
    try {
      writeFileSync(this.file, JSON.stringify([...this.byIntegrity.values()], null, 2));
    } catch {
      /* best-effort */
    }
  }
}
```

- [ ] **Step 4: Run the test**

```bash
npx tsx --test packages/proxy/test/approval-requests-store.test.ts
npm run build
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/approval-requests.ts packages/proxy/test/approval-requests-store.test.ts
git commit -m "feat(phase11): ApprovalRequestStore — integrity-keyed pending approval requests"
```

---

### Task 3: `/-/approval-requests` endpoints + auto-clear on decision + wiring

**Files:**
- Modify: `packages/proxy/src/server.ts` (ServerOptions, endpoints, clear-on-approval)
- Modify: `packages/proxy/src/index.ts` (construct + pass the store)
- Modify: `scripts/demo.ts` + every `createServer(...)` test call site (add `approvalRequests`)
- Test: `packages/proxy/test/approval-requests-e2e.test.ts`

**Interfaces:**
- Consumes: `ApprovalRequestStore` (Task 2).
- Produces (used by Task 6, Task 7): `ServerOptions.approvalRequests: ApprovalRequestStore`; `POST /-/approval-requests` (body `{ name, version, integrity, reason, requestedBy? }` → 400 if the integrity has no audited report), `GET /-/approval-requests`; the existing `POST /-/approvals` clears the matching pending request.

- [ ] **Step 1: Write the failing e2e test** (`packages/proxy/test/approval-requests-e2e.test.ts`)

```ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type AuditReport } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { ViolationStore } from "../src/violations.js";
import { ApprovalRequestStore } from "../src/approval-requests.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

describe("approval-requests (e2e)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  async function integrityOf(pkg: string, v: string): Promise<string> {
    return ((await (await fetch(`${base}/-/audit/${pkg}/${v}`)).json()) as AuditReport).meta.integrity!;
  }

  test("a request for an audited integrity is recorded and listed", async () => {
    const integrity = await integrityOf("net-fetch-lite", "1.0.0");
    const res = await fetch(`${base}/-/approval-requests`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.0", integrity, reason: "need fetch" }),
    });
    assert.equal(res.status, 200);
    const list = (await (await fetch(`${base}/-/approval-requests`)).json()) as { requests: { integrity: string; requestedBy: { type: string } }[] };
    assert.ok(list.requests.some((r) => r.integrity === integrity));
    assert.equal(list.requests.find((r) => r.integrity === integrity)?.requestedBy.type, "agent");
  });

  test("a request for an un-audited integrity is 400", async () => {
    const res = await fetch(`${base}/-/approval-requests`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "x", version: "1.0.0", integrity: "sha512-UNKNOWN", reason: "y" }),
    });
    assert.equal(res.status, 400);
  });

  test("recording an approval decision clears the matching pending request", async () => {
    const integrity = await integrityOf("net-fetch-lite", "1.0.0");
    await fetch(`${base}/-/approval-requests`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.0", integrity, reason: "need fetch" }),
    });
    await fetch(`${base}/-/approvals`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ integrity, decision: "approved" }),
    });
    const list = (await (await fetch(`${base}/-/approval-requests`)).json()) as { requests: { integrity: string }[] };
    assert.ok(!list.requests.some((r) => r.integrity === integrity), "the pending request must be cleared");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/approval-requests-e2e.test.ts
```

Expected: FAIL — `ServerOptions` has no `approvalRequests`; routes 404.

- [ ] **Step 3: Implement `server.ts`** — import + option:

```ts
import { ApprovalRequestStore } from "./approval-requests.js";
```

Add to `ServerOptions`:

```ts
  /** Pending approval requests store (agent asks, human grants) — Phase 11. */
  approvalRequests: ApprovalRequestStore;
```

Bind in `createServer`: `const approvalRequests = opts.approvalRequests;`

Endpoints (near the `/-/approvals` routes):

```ts
  app.post("/-/approval-requests", (req, res) => {
    const b = req.body as { name?: unknown; version?: unknown; integrity?: unknown; reason?: unknown; requestedBy?: { type?: string; id?: string } };
    if (typeof b?.name !== "string" || typeof b.version !== "string" || typeof b.integrity !== "string" || typeof b.reason !== "string") {
      return res.status(400).json({ error: "need name, version, integrity, reason" });
    }
    const audited = store.get(b.integrity);
    if (!audited) return res.status(400).json({ error: `audit ${b.name}@${b.version} first (no report for that integrity)` });
    const requestedBy = b.requestedBy?.type === "human" || b.requestedBy?.type === "agent"
      ? { type: b.requestedBy.type, id: String(b.requestedBy.id ?? "unknown") }
      : { type: "agent" as const, id: "mcp" };
    const rec = approvalRequests.record({
      name: audited.report.meta.name, version: audited.report.meta.version, integrity: b.integrity,
      reason: b.reason, requestedBy, capabilities: audited.report.capabilities,
    });
    res.json({ requested: rec });
  });

  app.get("/-/approval-requests", (_req, res) => {
    res.json({ requests: approvalRequests.recent(50) });
  });
```

In the existing `POST /-/approvals` handler, after `recorded.push(approvals.put({...}))`, add `approvalRequests.clear(d.integrity);` so a decision drops its pending request.

- [ ] **Step 4: Wire `index.ts`** — import, construct with `process.env.SENTINEL_APPROVAL_REQUESTS`, pass in `createServer({...})`, and add a boot log line. Also add `export { ApprovalRequestStore } from "./approval-requests.js";` beside the other store exports.

- [ ] **Step 5: Fix every other `createServer(...)` call site** — add `approvalRequests: new ApprovalRequestStore()` to each (the same set touched in Phase 10 for `violations`: the proxy test files + `scripts/demo.ts`). The compiler flags them; this is mechanical and required. Import `ApprovalRequestStore` in each.

- [ ] **Step 6: Build + run**

```bash
npm run build
npx tsx --test packages/proxy/test/approval-requests-e2e.test.ts packages/proxy/test/approvals.test.ts
npm test 2>&1 | tail -4
```

Expected: PASS; full suite green.

- [ ] **Step 7: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/src/index.ts scripts/demo.ts packages/proxy/test
git commit -m "feat(phase11): /-/approval-requests endpoints + auto-clear on approval decision"
```

---

### Task 4: `packages/mcp` scaffold + `ProxyClient`

**Files:**
- Create: `packages/mcp/package.json`, `packages/mcp/tsconfig.json`
- Modify: root `tsconfig.json` (add the reference)
- Create: `packages/mcp/src/client.ts`
- Test: `packages/mcp/test/client.test.ts`

**Interfaces:**
- Produces (used by Tasks 5–7):
  - `class ProxyError extends Error { constructor(message: string, readonly status?: number) }`
  - `class ProxyClient` constructed `new ProxyClient(baseUrl: string)` with methods returning parsed JSON or throwing `ProxyError`: `audit(pkg, version?)`, `manifest(pkg, version)`, `auditTree(coords)`, `violations()`, `approvalRequest(body)`. `audit`/`manifest` resolve `version` to latest via the packument when omitted (see below).

- [ ] **Step 1: Create `packages/mcp/package.json`**

```json
{
  "name": "@sentinel/mcp",
  "version": "0.1.0",
  "description": "Sentinel MCP server: agent-native pre-install audit tools backed by the proxy.",
  "license": "Apache-2.0",
  "type": "module",
  "main": "./dist/index.js",
  "bin": { "sentinel-mcp": "./dist/index.js" },
  "dependencies": {
    "@sentinel/core": "0.1.0",
    "@modelcontextprotocol/sdk": "^1.29.0",
    "zod": "^3.23.8"
  },
  "devDependencies": { "@types/node": "^24.13.2" }
}
```

- [ ] **Step 2: Create `packages/mcp/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "rootDir": "src", "outDir": "dist" },
  "include": ["src/**/*.ts"],
  "references": [{ "path": "../core" }]
}
```

- [ ] **Step 3: Add the reference to root `tsconfig.json`** — add `{ "path": "packages/mcp" }` to the `references` array.

- [ ] **Step 4: Install deps** — `npm install` (root; the workspace picks up the new deps).

- [ ] **Step 5: Write the failing test** (`packages/mcp/test/client.test.ts`) — drive the client against an in-process proxy:

```ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../../proxy/src/server.js";
import { AuditStore } from "../../proxy/src/store.js";
import { LocalFixtureUpstream } from "../../proxy/src/upstream.js";
import { ApprovalStore } from "../../proxy/src/approvals.js";
import { PrivatePackageStore } from "../../proxy/src/private-store.js";
import { ViolationStore } from "../../proxy/src/violations.js";
import { ApprovalRequestStore } from "../../proxy/src/approval-requests.js";
import { ProxyClient, ProxyError } from "../src/client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

describe("ProxyClient", () => {
  let server: Server; let client: ProxyClient;
  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
      approvalRequests: new ApprovalRequestStore(),
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { client = new ProxyClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}`); r(); }); });
  });
  after(() => server?.close());

  test("audit returns the real verdict for a blocking fixture", async () => {
    const rep = await client.audit("color-stream", "1.4.1");
    assert.equal(rep.verdict, "block");
  });

  test("audit resolves latest when version omitted", async () => {
    const rep = await client.audit("leftpad-lite");
    assert.equal(rep.meta.name, "leftpad-lite");
    assert.equal(rep.verdict, "allow");
  });

  test("an unknown package throws ProxyError with the status", async () => {
    await assert.rejects(() => client.audit("does-not-exist", "1.0.0"), (e) => e instanceof ProxyError && e.status === 404);
  });

  test("a bad base URL throws ProxyError (connection refused), not a fake verdict", async () => {
    const bad = new ProxyClient("http://127.0.0.1:1");
    await assert.rejects(() => bad.audit("x", "1.0.0"), (e) => e instanceof ProxyError);
  });
});
```

- [ ] **Step 6: Run to verify it fails**

```bash
npx tsx --test packages/mcp/test/client.test.ts
```

Expected: FAIL — cannot find module `../src/client.js`.

- [ ] **Step 7: Implement `packages/mcp/src/client.ts`**

```ts
import type { AuditReport } from "@sentinel/core";

export class ProxyError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "ProxyError";
  }
}

/** Shape of the /-/manifest response (a superset of the audit fields the tools use). */
export interface ManifestResponse {
  meta: AuditReport["meta"];
  score: number;
  verdict: string;
  findings: AuditReport["findings"];
  capabilities: AuditReport["capabilities"];
  capabilityDelta: AuditReport["capabilityDelta"];
  approvalRequired: AuditReport["capabilities"];
  approvalState: string;
  inheritedFrom: string | null;
}

export interface ViolationRecordDTO {
  name: string; version: string; integrity: string;
  kind: string; target: string | null; confidence: string;
  quarantined: boolean;
}

/** Thin HTTP client over the proxy's /-/* endpoints. Every method returns parsed
 *  JSON or throws ProxyError — never a fabricated verdict. */
export class ProxyClient {
  constructor(private readonly baseUrl: string) {}

  private async getJson<T>(path: string): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, { headers: { accept: "application/json" } });
    } catch (e) {
      throw new ProxyError(`cannot reach Sentinel proxy at ${this.baseUrl}: ${(e as Error).message}`);
    }
    if (!res.ok) {
      throw new ProxyError(`proxy ${path} returned ${res.status}: ${await safeText(res)}`, res.status);
    }
    return (await res.json()) as T;
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, {
        method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify(body),
      });
    } catch (e) {
      throw new ProxyError(`cannot reach Sentinel proxy at ${this.baseUrl}: ${(e as Error).message}`);
    }
    if (!res.ok) throw new ProxyError(`proxy ${path} returned ${res.status}: ${await safeText(res)}`, res.status);
    return (await res.json()) as T;
  }

  /** Resolve latest via the packument's dist-tags when version is omitted. */
  private async resolveVersion(pkg: string, version?: string): Promise<string> {
    if (version) return version;
    const doc = await this.getJson<{ "dist-tags"?: Record<string, string> }>(`/${encodeURIComponent(pkg).replace("%40", "@")}`);
    const latest = doc["dist-tags"]?.latest;
    if (!latest) throw new ProxyError(`no latest version for ${pkg}`);
    return latest;
  }

  async audit(pkg: string, version?: string): Promise<AuditReport> {
    const v = await this.resolveVersion(pkg, version);
    return this.getJson<AuditReport>(`/-/audit/${encodeURIComponent(pkg)}/${encodeURIComponent(v)}`);
  }

  async manifest(pkg: string, version?: string): Promise<ManifestResponse> {
    const v = await this.resolveVersion(pkg, version);
    return this.getJson<ManifestResponse>(`/-/manifest/${encodeURIComponent(pkg)}/${encodeURIComponent(v)}`);
  }

  async auditTree(packages: { name: string; version: string }[]): Promise<{ aggregate: { verdict: string; gated: boolean; counts: Record<string, number> }; packages: unknown[] }> {
    return this.postJson(`/-/audit-tree`, { packages });
  }

  async violations(): Promise<ViolationRecordDTO[]> {
    return (await this.getJson<{ violations: ViolationRecordDTO[] }>(`/-/violations`)).violations;
  }

  async approvalRequest(body: { name: string; version: string; integrity: string; reason: string; requestedBy?: { type: "agent" | "human"; id: string } }): Promise<unknown> {
    return this.postJson(`/-/approval-requests`, body);
  }
}

async function safeText(res: Response): Promise<string> {
  try { return (await res.text()).slice(0, 200); } catch { return ""; }
}
```

- [ ] **Step 8: Run the test + build**

```bash
npm run build
npx tsx --test packages/mcp/test/client.test.ts
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add packages/mcp/package.json packages/mcp/tsconfig.json tsconfig.json package-lock.json packages/mcp/src/client.ts packages/mcp/test/client.test.ts
git commit -m "feat(phase11): packages/mcp scaffold + ProxyClient (thin, fail-explicit /-/ client)"
```

---

### Task 5: Tool handlers + formatters

**Files:**
- Create: `packages/mcp/src/format.ts`
- Create: `packages/mcp/src/tools.ts`
- Test: `packages/mcp/test/tools.test.ts`

**Interfaces:**
- Consumes: `ProxyClient` (Task 4), `parseLockfile` (Task 1).
- Produces (used by Task 6): an array `TOOLS` of `{ name: string; description: string; inputSchema: Record<string, z.ZodType>; handler(args, client: ProxyClient): Promise<{ text: string; structured: unknown }> }`. Names: `sentinel_audit`, `sentinel_audit_tree`, `sentinel_capabilities`, `sentinel_check_provenance`, `sentinel_list_violations`, `sentinel_request_approval`.

- [ ] **Step 1: Write the failing test** (`packages/mcp/test/tools.test.ts`) — drive handlers directly against an in-process-proxy-backed client (reuse the boot boilerplate from client.test.ts; only the assertions differ):

```ts
// ... same imports + before/after booting an in-process proxy and a ProxyClient `client` ...
import { TOOLS } from "../src/tools.js";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

const byName = (n: string) => TOOLS.find((t) => t.name === n)!;

test("sentinel_audit surfaces verdict + score for a blocking fixture", async () => {
  const r = await byName("sentinel_audit").handler({ package: "color-stream", version: "1.4.1" }, client);
  const s = r.structured as { verdict: string; quarantined: boolean };
  assert.equal(s.verdict, "block");
  assert.equal(s.quarantined, false);
  assert.match(r.text, /block/i);
});

test("sentinel_audit reports quarantined:true after a confirmed violation is recorded", async () => {
  const rep = await client.audit("leftpad-lite", "1.0.0");
  await fetch(`${base}/-/violations`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "leftpad-lite", version: "1.0.0", integrity: rep.meta.integrity,
      kind: "filesystem", target: "/x/.ssh/id_rsa", confidence: "confirmed", deniedResource: "/x/.ssh",
      evidence: { exitCode: 1, stderrExcerpt: "EPERM" } }) });
  const r = await byName("sentinel_audit").handler({ package: "leftpad-lite", version: "1.0.0" }, client);
  assert.equal((r.structured as { quarantined: boolean }).quarantined, true);
});

test("sentinel_capabilities returns the manifest + approval state", async () => {
  const r = await byName("sentinel_capabilities").handler({ package: "net-fetch-lite", version: "1.0.0" }, client);
  const s = r.structured as { capabilities: unknown[]; approvalState: string };
  assert.ok(Array.isArray(s.capabilities));
  assert.ok(typeof s.approvalState === "string");
});

test("sentinel_check_provenance projects provenance status", async () => {
  const r = await byName("sentinel_check_provenance").handler({ package: "leftpad-lite", version: "1.0.0" }, client);
  assert.ok(["verified", "invalid", "absent", "unknown"].includes((r.structured as { provenance: string }).provenance));
});

test("sentinel_audit_tree parses a lockfile and returns an aggregate", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mcp-lock-"));
  const lock = join(dir, "package-lock.json");
  writeFileSync(lock, JSON.stringify({ lockfileVersion: 3, packages: {
    "": { name: "root" },
    "node_modules/leftpad-lite": { version: "1.0.0" },
  } }));
  const r = await byName("sentinel_audit_tree").handler({ lockfile: lock }, client);
  assert.ok(["allow", "warn", "block"].includes((r.structured as { verdict: string }).verdict));
});

test("sentinel_list_violations returns recorded violations", async () => {
  const r = await byName("sentinel_list_violations").handler({}, client);
  assert.ok(Array.isArray((r.structured as { violations: unknown[] }).violations));
});

test("sentinel_request_approval records a pending request (does NOT approve)", async () => {
  const r = await byName("sentinel_request_approval").handler({ package: "net-fetch-lite", version: "1.0.0", reason: "need fetch" }, client);
  assert.match(r.text, /request/i);
  const list = (await (await fetch(`${base}/-/approval-requests`)).json()) as { requests: unknown[] };
  assert.equal(list.requests.length >= 1, true);
  // and it did NOT create an approval:
  const approvals = (await (await fetch(`${base}/-/approvals`)).json()) as { approvals: unknown[] };
  assert.equal(approvals.approvals.length, 0);
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/mcp/test/tools.test.ts
```

Expected: FAIL — cannot find module `../src/tools.js`.

- [ ] **Step 3: Implement `packages/mcp/src/format.ts`**

```ts
import type { AuditReport } from "@sentinel/core";

export function summarizeAudit(r: AuditReport, quarantined: boolean): string {
  const lines = [
    `${r.meta.name}@${r.meta.version} — verdict ${r.verdict.toUpperCase()} (score ${r.score}/100)`,
    `signature: ${r.meta.signature} · provenance: ${r.meta.provenance}${quarantined ? " · ⚠ QUARANTINED (runtime violation recorded)" : ""}`,
    `install scripts: ${r.meta.hasInstallScripts ? "yes" : "no"} · capabilities: ${r.capabilities.length}`,
  ];
  if (r.findings.length) {
    lines.push(`findings (${r.findings.length}):`);
    for (const f of r.findings.slice(0, 5)) lines.push(`  [${f.severity}] ${f.ruleId}: ${f.message}`);
  }
  return lines.join("\n");
}
```

- [ ] **Step 4: Implement `packages/mcp/src/tools.ts`**

```ts
import { readFileSync } from "node:fs";
import { z } from "zod";
import { parseLockfile } from "@sentinel/core";
import type { ProxyClient } from "./client.js";
import { summarizeAudit } from "./format.js";

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, z.ZodType>;
  handler(args: Record<string, unknown>, client: ProxyClient): Promise<{ text: string; structured: unknown }>;
}

async function isQuarantined(client: ProxyClient, integrity: string | null): Promise<boolean> {
  if (!integrity) return false;
  const v = await client.violations();
  return v.some((x) => x.integrity === integrity && x.quarantined);
}

export const TOOLS: ToolDef[] = [
  {
    name: "sentinel_audit",
    description: "Audit an npm package version before installing: verdict, score, findings, capabilities, signature/provenance status, and whether it is quarantined by a runtime violation.",
    inputSchema: { package: z.string(), version: z.string().optional() },
    async handler(args, client) {
      const rep = await client.audit(args.package as string, args.version as string | undefined);
      const quarantined = await isQuarantined(client, rep.meta.integrity);
      return {
        text: summarizeAudit(rep, quarantined),
        structured: {
          package: rep.meta.name, version: rep.meta.version, verdict: rep.verdict, score: rep.score,
          quarantined, signature: rep.meta.signature, provenance: rep.meta.provenance,
          hasInstallScripts: rep.meta.hasInstallScripts,
          capabilities: rep.capabilities, findings: rep.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
        },
      };
    },
  },
  {
    name: "sentinel_audit_tree",
    description: "Audit every package in an npm package-lock.json and return the aggregate verdict, whether the tree is gated, and the worst offenders.",
    inputSchema: { lockfile: z.string() },
    async handler(args, client) {
      const coords = parseLockfile(readFileSync(args.lockfile as string, "utf8"));
      const result = await client.auditTree(coords.map((c) => ({ name: c.name, version: c.version })));
      return {
        text: `tree: ${result.aggregate.verdict.toUpperCase()}${result.aggregate.gated ? " (GATED)" : ""} · ` +
          Object.entries(result.aggregate.counts).map(([k, v]) => `${v} ${k}`).join(" · "),
        structured: result,
      };
    },
  },
  {
    name: "sentinel_capabilities",
    description: "Show a package's capability manifest (network/filesystem/process/env/native), the delta vs the prior version, and its approval state.",
    inputSchema: { package: z.string(), version: z.string().optional() },
    async handler(args, client) {
      const m = await client.manifest(args.package as string, args.version as string | undefined);
      return {
        text: `${m.meta.name}@${m.meta.version} — ${m.capabilities.length} capabilities · approval: ${m.approvalState}` +
          (m.approvalRequired.length ? ` · ${m.approvalRequired.length} need approval` : ""),
        structured: { capabilities: m.capabilities, capabilityDelta: m.capabilityDelta, approvalState: m.approvalState, approvalRequired: m.approvalRequired },
      };
    },
  },
  {
    name: "sentinel_check_provenance",
    description: "Report a package's build-provenance status (verified/invalid/absent/unknown) and, when verified, the source repo, workflow, builder, and commit.",
    inputSchema: { package: z.string(), version: z.string().optional() },
    async handler(args, client) {
      const rep = await client.audit(args.package as string, args.version as string | undefined);
      const id = rep.meta.provenanceIdentity ?? null;
      return {
        text: `${rep.meta.name}@${rep.meta.version} — provenance ${rep.meta.provenance}` +
          (id ? `\nbuilt by ${id.builder ?? "?"} from ${id.sourceRepository ?? "?"}${id.ref ? `@${id.ref}` : ""}${id.commit ? ` (${id.commit.slice(0, 7)})` : ""}` : ""),
        structured: { provenance: rep.meta.provenance, provenanceIdentity: id, signature: rep.meta.signature },
      };
    },
  },
  {
    name: "sentinel_list_violations",
    description: "List runtime violations the sandbox has recorded, and which package builds are quarantined.",
    inputSchema: { package: z.string().optional() },
    async handler(args, client) {
      let violations = await client.violations();
      if (args.package) violations = violations.filter((v) => v.name === args.package);
      return {
        text: violations.length ? violations.map((v) => `${v.quarantined ? "QUARANTINED" : v.confidence} ${v.name}@${v.version} ${v.kind} → ${v.target ?? "?"}`).join("\n") : "no runtime violations recorded",
        structured: { violations },
      };
    },
  },
  {
    name: "sentinel_request_approval",
    description: "Request that a human approve installing a package whose capabilities need approval. Records a pending request; it does NOT grant approval.",
    inputSchema: { package: z.string(), version: z.string().optional(), reason: z.string() },
    async handler(args, client) {
      const rep = await client.audit(args.package as string, args.version as string | undefined);
      await client.approvalRequest({ name: rep.meta.name, version: rep.meta.version, integrity: rep.meta.integrity!, reason: args.reason as string });
      return {
        text: `Recorded an approval request for ${rep.meta.name}@${rep.meta.version} (current verdict: ${rep.verdict}). A human must approve it in the Sentinel dashboard before install proceeds.`,
        structured: { requested: true, package: rep.meta.name, version: rep.meta.version, verdict: rep.verdict },
      };
    },
  },
];
```

- [ ] **Step 5: Run the test + build**

```bash
npm run build
npx tsx --test packages/mcp/test/tools.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/mcp/src/format.ts packages/mcp/src/tools.ts packages/mcp/test/tools.test.ts
git commit -m "feat(phase11): MCP tool handlers (audit/tree/capabilities/provenance/violations/request_approval) + formatter"
```

---

### Task 6: MCP server bootstrap + end-to-end transport test

**Files:**
- Create: `packages/mcp/src/index.ts`
- Test: `packages/mcp/test/server-e2e.test.ts`

**Interfaces:**
- Consumes: `TOOLS` (Task 5), `ProxyClient` (Task 4), the MCP SDK.
- Produces: an exported `createMcpServer(client: ProxyClient): McpServer` (registers every tool), plus a `main()` that builds the client from `SENTINEL_PROXY` and connects stdio. The exported factory is what the e2e test drives via `InMemoryTransport`.

- [ ] **Step 1: Write the failing e2e test** (`packages/mcp/test/server-e2e.test.ts`) — boot an in-process proxy + client (same boilerplate), wire the MCP server to a linked in-memory client:

```ts
// ... same in-process-proxy + ProxyClient boot boilerplate producing `client` and `base` ...
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/index.js";

test("tools are registered and round-trip over the transport", async () => {
  const server = createMcpServer(client);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  const mcp = new Client({ name: "test", version: "0.0.0" });
  await mcp.connect(clientT);

  const tools = await mcp.listTools();
  const names = tools.tools.map((t) => t.name).sort();
  assert.deepEqual(names, [
    "sentinel_audit", "sentinel_audit_tree", "sentinel_capabilities",
    "sentinel_check_provenance", "sentinel_list_violations", "sentinel_request_approval",
  ].sort());

  const res = await mcp.callTool({ name: "sentinel_audit", arguments: { package: "color-stream", version: "1.4.1" } });
  assert.match((res.content as { text: string }[])[0].text, /block/i);
  assert.equal((res.structuredContent as { verdict: string }).verdict, "block");

  const bad = await mcp.callTool({ name: "sentinel_audit", arguments: { package: 123 } });
  assert.equal(bad.isError, true); // SDK schema validation rejects a non-string package
  await mcp.close();
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/mcp/test/server-e2e.test.ts
```

Expected: FAIL — cannot find module `../src/index.js`.

- [ ] **Step 3: Implement `packages/mcp/src/index.ts`**

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ProxyClient, ProxyError } from "./client.js";
import { TOOLS } from "./tools.js";

/** Build an McpServer with every Sentinel tool registered against `client`. */
export function createMcpServer(client: ProxyClient): McpServer {
  const server = new McpServer({ name: "sentinel", version: "0.1.0" });
  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      { description: tool.description, inputSchema: tool.inputSchema },
      async (args: Record<string, unknown>) => {
        try {
          const { text, structured } = await tool.handler(args, client);
          return { content: [{ type: "text" as const, text }], structuredContent: structured as Record<string, unknown> };
        } catch (e) {
          const msg = e instanceof ProxyError ? e.message : `tool ${tool.name} failed: ${(e as Error).message}`;
          return { content: [{ type: "text" as const, text: msg }], isError: true };
        }
      },
    );
  }
  return server;
}

async function main(): Promise<void> {
  const client = new ProxyClient(process.env.SENTINEL_PROXY ?? "http://localhost:4873");
  const server = createMcpServer(client);
  await server.connect(new StdioServerTransport());
}

// Run only when invoked as the entrypoint (not when imported by a test).
import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
function isMain(): boolean {
  const a = process.argv[1];
  if (!a) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(a)).href; } catch { return false; }
}
if (isMain()) main().catch((e) => { console.error(`sentinel-mcp: ${(e as Error).message}`); process.exit(1); });
```

Note the `isMain()` guard uses `realpathSync` (the Phase 10 lesson — a loose `endsWith("index.js")` guard would fire on import from another `index.js`).

- [ ] **Step 4: Run the e2e + build**

```bash
npm run build
npx tsx --test packages/mcp/test/server-e2e.test.ts
```

Expected: PASS — 6 tools registered, audit round-trips block, bad input → isError.

- [ ] **Step 5: Full suite**

```bash
npm test 2>&1 | tail -5
```

Expected: green (record counts).

- [ ] **Step 6: Commit**

```bash
git add packages/mcp/src/index.ts packages/mcp/test/server-e2e.test.ts
git commit -m "feat(phase11): MCP server bootstrap (stdio) + in-memory-transport e2e; entrypoint-guarded main"
```

---

### Task 7: Dashboard pending-requests panel

**Files:**
- Modify: `packages/proxy/public/index.html`

**Interfaces:**
- Consumes: `GET /-/approval-requests` (Task 3), `POST /-/approvals` (existing).

- [ ] **Step 1: Add the panel + CSS** — in `index.html`, after the Approvals panel add a "Pending approval requests" section: a `<table id="request-rows">` with columns Package / Requester / Reason / Capabilities / (Approve|Deny). Reuse the existing `esc()` helper on every interpolated field.

- [ ] **Step 2: Add the fetch/render/actions JS** — mirror `loadApprovals`:

```js
function requestRow(r) {
  const caps = (r.capabilities || []).map((c) => `${c.kind}:${c.target}`).join(", ") || "none";
  return `<tr>
    <td><div class="pkg">${esc(r.name)}</div><div class="meta">v${esc(r.version)}</div></td>
    <td class="meta">${esc(r.requestedBy ? r.requestedBy.type + ":" + r.requestedBy.id : "—")}</td>
    <td class="meta">${esc(r.reason || "")}</td>
    <td class="meta">${esc(caps)}</td>
    <td>
      <button class="ghost" data-approve="${esc(r.integrity)}">Approve</button>
      <button class="ghost" data-deny="${esc(r.integrity)}">Deny</button>
    </td>
  </tr>`;
}

async function loadRequests() {
  const data = await (await fetch("/-/approval-requests")).json();
  const rows = data.requests || [];
  $("request-rows").innerHTML = rows.length ? rows.map(requestRow).join("")
    : '<tr><td colspan="5" class="empty">No pending requests.</td></tr>';
  for (const btn of document.querySelectorAll("[data-approve],[data-deny]")) {
    btn.addEventListener("click", async () => {
      const approve = btn.hasAttribute("data-approve");
      const integrity = btn.getAttribute(approve ? "data-approve" : "data-deny");
      await fetch("/-/approvals", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ integrity, decision: approve ? "approved" : "denied" }) });
      await loadRequests();
    });
  }
}
```

Add `loadRequests()` to the initial load and the `setInterval` refresh (alongside `loadApprovals`/`loadViolations`).

- [ ] **Step 3: Boot check (offline, fixtures)**

```bash
npm run build
SENTINEL_UPSTREAM=fixtures SENTINEL_BOOT_EXIT=1 node packages/proxy/dist/index.js
```

Expected: boots and exits clean (the panel is static HTML+JS; no server-side test needed — the endpoint behavior is covered by Task 3).

- [ ] **Step 4: Commit**

```bash
git add packages/proxy/public/index.html
git commit -m "feat(phase11): dashboard pending approval-requests panel with Approve/Deny"
```

---

### Task 8: Docs, ADR-0024, final verification

**Files:**
- Create: `docs/adr/0024-agent-native-mcp-surface.md`
- Modify: `ARCHITECTURE.md` (§4 client-integration + §5 store list)
- Modify: `CLAUDE.md` (What-this-is phase list; test-count line)
- Modify: `README.md` (MCP setup block + tool list; `sentinel-mcp` bin; `/-/approval-requests` endpoints; `SENTINEL_APPROVAL_REQUESTS` env)

- [ ] **Step 1: Write ADR-0024** — follow the house style of `docs/adr/0023-runtime-violation-telemetry.md`. Required content: **Context** (agent-auditable product, no agent interface after 10 phases). **Decision** (thin stdio MCP client to the proxy via `@modelcontextprotocol/sdk`; five read tools + `request_approval`; new `ApprovalRequestStore` + `/-/approval-requests`; `parseLockfile` moved to core; quarantine projected from `/-/violations` since it's a serve-time overlay). **Privilege boundary** (the agent requests, never grants — `request_approval` records a pending request a human resolves; auto-approve/clear-quarantine tools deliberately never exist; ADR-0013 fail-closed preserved). **Auth posture** (no MCP↔proxy auth this phase; the write path only requests; authenticating the hop is the follow-on with the API-auth phase). **Consequences** (verdict is byte-identical to a real install; the MCP layer does zero scoring — invariant #1 untouched; a proxy error fails explicitly, never a fabricated verdict). **Deferred** (MCP↔proxy auth; HTTP/SSE + remote hosting; an install tool; embedded-core offline mode). **Rejected** (embed-core — different verdict than a real install; hybrid — silent offline fallback could report block as allow). Extends ADR-0001/0007/0013/0002.

- [ ] **Step 2: ARCHITECTURE.md** — in the §4 client-integration section, add the MCP surface (stdio server, thin proxy client, the six tools, the request-not-grant boundary). In §5 (store list, if present), add `ApprovalRequestStore`.

- [ ] **Step 3: CLAUDE.md** — add the Phase 11 sentence to "What this is" (mirror Phase 10's density: agent-native MCP surface, thin proxy client, read tools + request_approval, `parseLockfile` moved to core). Update the `npm test` count line with the ACTUAL number from Step 5 (preserve the darwin-skip caveats).

- [ ] **Step 4: README.md** — an MCP setup block (agent-host config: `command: "node"`, `args: ["packages/mcp/dist/index.js"]`, `env: { SENTINEL_PROXY }`), the six-tool list, the `sentinel-mcp` bin, the `/-/approval-requests` endpoints, and the `SENTINEL_APPROVAL_REQUESTS` persistence env var.

- [ ] **Step 5: Full Definition-of-Done run**

```bash
npm run build
npm run fixtures
npm test 2>&1 | tail -8
npm run demo 2>&1 | tail -3
```

Expected: build clean; ALL tests pass (record exact count for CLAUDE.md); demo still blocks the malicious fixture. If the count differs from CLAUDE.md, update the doc to reality.

- [ ] **Step 6: Commit**

```bash
git add docs ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase11): ADR-0024 agent-native MCP surface; ARCHITECTURE §4/§5; CLAUDE/README updates"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture (packages/mcp, client, tools, format) → Tasks 4/5/6; §2 read tools → Task 5 (+ the quarantine projection from `/-/violations`, tested); §3 request_approval + store + endpoint + dashboard → Tasks 2/3/5/7; §4 config/error/testing/DoD → Tasks 4–6 (in-memory transport e2e, proxy-unreachable test, invariant-#1 note) + Task 8. `parseLockfile` reuse → Task 1 (moved to core, avoids the mcp→cli argv-guard footgun).
- **Type consistency:** `ProxyClient`/`ProxyError` (Task 4) consumed by name in Tasks 5/6; `ToolDef`/`TOOLS` (Task 5) consumed by `createMcpServer` (Task 6); `ApprovalRequest`/`ApprovalRequestStore` (Task 2) → endpoints (Task 3) → `requestedBy` agent default; tool names identical between Task 5 defs and the Task 6 e2e assertion list; `Coordinate`/`parseLockfile` (Task 1) → Task 5 audit_tree handler.
- **Known judgment calls:** `parseLockfile` moved to core (not imported from cli) to avoid the `argv[1].endsWith("index.js")` parse-guard firing on import from mcp's own `index.js`; the MCP server uses the same `realpathSync` entrypoint guard hardened in Phase 10; quarantine is projected from `/-/violations` (not the cached report) per the Phase 10 serve-time-overlay design; input validation is the SDK's (zod), not hand-rolled (probed).

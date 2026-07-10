# Phase 24 — Resource Robustness (ADR-0037) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound the work any single request can force on the proxy: cap and dedupe audit-tree fan-out, cap tarball/packument download bytes, coalesce concurrent uncached audits, and add opt-in per-source rate limiting on expensive open endpoints.

**Architecture:** Two new pure modules — `packages/proxy/src/limits.ts` (numeric env parsing + a byte-capped response-body reader) and `packages/proxy/src/rate-limit.ts` (token bucket with injectable clock). `NpmUpstream` gains two byte caps enforced inside its existing `fetchPinned` path; `createServer` gains tree dedupe+cap, an in-flight coalescing map, and a rate-limit middleware gate; `index.ts` wires four fail-closed env vars.

**Tech Stack:** Node 24 / TypeScript, Express 5, undici `fetch` (web `Response`/`ReadableStream`), `node:test` + `tsx`.

**Spec:** `docs/superpowers/specs/2026-07-09-resource-robustness-design.md`.

## Global Constraints

- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts` sources.
- Tests hermetic: local `127.0.0.1` listeners or in-memory `Response` objects only; never hit live npm. `LocalFixtureUpstream` is disk-backed and MUST stay untouched.
- Fail-closed env posture: a set-but-invalid env var is `console.error("FATAL: …")` + `process.exit(1)` at startup (mirror `resolvePublicBaseUrl` in `packages/proxy/src/index.ts:144`).
- No scoring changes — invariants #1–#2 untouched. Integrity hash stays the durable cache key (#4). Packument passthrough still rewrites only `dist.tarball` (#5). Rules still fail open (#6).
- Byte caps are plain integer **bytes** (no "256MB" string parsing). Defaults expressed in code as `N * 1024 * 1024`.
- Rate limiting keyed by `req.socket.remoteAddress` (never `X-Forwarded-For`). Injectable clock — no `Date.now()` inside the pure module.
- Rate limiting applies ONLY to `POST /-/audit-tree`, `GET /-/explain/*`, `POST /-/policy/preview`. Gate paths (tarball/packument) are never rate-limited.
- Child-process boot tests use **async** `execFile` (promisified), never `execFileSync` (deadlocks the in-process proxy).
- Run one test file: `node --import tsx --test packages/proxy/test/<file>.test.ts` from the repo root. Full suite: `npm test`.
- Build: `npm run build`. If `rm` of `dist/` fails with EPERM, use `npx tsc --build --force packages/proxy`.
- Commit style: `feat(phase24): …` / `test(phase24): …` / `docs(phase24): …`.
- Current full-suite baseline on darwin (post-Phase-23): **580 tests, 578 pass, 2 skipped**.

---

### Task 1: Pure limits helpers — numeric env parse + byte-capped body reader

**Files:**
- Create: `packages/proxy/src/limits.ts`
- Test: `packages/proxy/test/limits.test.ts`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces (used by Tasks 2, 3, 6, 7):
  - `parsePositiveInt(raw: string, name: string): number` — throws `Error` on non-integer, ≤0, or NaN.
  - `readBodyCapped(res: Response, maxBytes: number, what: string): Promise<Buffer>` — throws `Error` if `content-length` exceeds `maxBytes`, or if the streamed body exceeds `maxBytes`; otherwise returns the full body Buffer.

- [ ] **Step 1: Write the failing tests**

```typescript
// packages/proxy/test/limits.test.ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { describe, test } from "node:test";
import { parsePositiveInt, readBodyCapped } from "../src/limits.js";

describe("parsePositiveInt", () => {
  test("parses a positive integer", () => {
    assert.equal(parsePositiveInt("5000", "SENTINEL_MAX_TREE_PACKAGES"), 5000);
  });
  test("rejects zero", () => {
    assert.throws(() => parsePositiveInt("0", "X"), /X must be a positive integer/);
  });
  test("rejects a negative number", () => {
    assert.throws(() => parsePositiveInt("-3", "X"), /positive integer/);
  });
  test("rejects a non-integer", () => {
    assert.throws(() => parsePositiveInt("3.5", "X"), /positive integer/);
  });
  test("rejects garbage", () => {
    assert.throws(() => parsePositiveInt("lots", "X"), /positive integer/);
  });
  test("rejects trailing junk", () => {
    assert.throws(() => parsePositiveInt("100MB", "X"), /positive integer/);
  });
});

/** Build a Response whose body streams `chunks`, with an optional content-length header. */
function streamResponse(chunks: Buffer[], contentLength?: number): Response {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(new Uint8Array(c));
      controller.close();
    },
  });
  const headers: Record<string, string> = {};
  if (contentLength !== undefined) headers["content-length"] = String(contentLength);
  return new Response(stream, { headers });
}

describe("readBodyCapped", () => {
  test("returns the full body when under the cap", async () => {
    const res = streamResponse([Buffer.from("hello "), Buffer.from("world")]);
    const buf = await readBodyCapped(res, 1000, "test body");
    assert.equal(buf.toString(), "hello world");
  });

  test("early-rejects when content-length exceeds the cap (body never read)", async () => {
    let bodyRead = false;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) { bodyRead = true; controller.enqueue(new Uint8Array(Buffer.from("x"))); controller.close(); },
    });
    const res = new Response(stream, { headers: { "content-length": "999999" } });
    await assert.rejects(() => readBodyCapped(res, 10, "test body"), /too large/);
    assert.equal(bodyRead, false, "body must not be read when content-length already exceeds the cap");
  });

  test("aborts mid-stream when the running total exceeds the cap (lying/absent content-length)", async () => {
    // No content-length; body is 100 bytes but cap is 10.
    const res = streamResponse([Buffer.alloc(6, 1), Buffer.alloc(6, 2)]);
    await assert.rejects(() => readBodyCapped(res, 10, "test body"), /too large/);
  });

  test("a body exactly at the cap is allowed", async () => {
    const res = streamResponse([Buffer.alloc(10, 7)]);
    const buf = await readBodyCapped(res, 10, "test body");
    assert.equal(buf.length, 10);
  });

  test("a null body yields an empty buffer", async () => {
    const res = new Response(null);
    const buf = await readBodyCapped(res, 10, "test body");
    assert.equal(buf.length, 0);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --import tsx --test packages/proxy/test/limits.test.ts`
Expected: FAIL — `Cannot find module '../src/limits.js'`

- [ ] **Step 3: Write the implementation**

```typescript
// packages/proxy/src/limits.ts
import { Buffer } from "node:buffer";

/**
 * Resource-limit helpers (Phase 24, ADR-0037). Pure — no I/O beyond consuming
 * a Response body stream, no env access (index.ts owns the FATAL wrapping).
 */

/** Parse a strictly-positive integer env value. Throws (caller FATALs) on anything else. */
export function parsePositiveInt(raw: string, name: string): number {
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  return n;
}

/**
 * Read a fetch Response body into a Buffer, refusing to buffer more than
 * `maxBytes`. Two layers: reject up front if the declared content-length
 * already exceeds the cap (body never read), and abort mid-stream if the
 * running byte total exceeds the cap (content-length can lie or be absent).
 * Bounds per-fetch memory to the cap instead of letting `arrayBuffer()`/`json()`
 * buffer an unbounded body first.
 */
export async function readBodyCapped(res: Response, maxBytes: number, what: string): Promise<Buffer> {
  const declared = res.headers.get("content-length");
  if (declared !== null) {
    const len = Number(declared);
    if (Number.isFinite(len) && len > maxBytes) {
      throw new Error(`${what} too large: content-length ${len} exceeds cap ${maxBytes}`);
    }
  }
  if (!res.body) return Buffer.alloc(0);

  const chunks: Buffer[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(`${what} too large: streamed ${total}+ bytes exceeds cap ${maxBytes}`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --import tsx --test packages/proxy/test/limits.test.ts`
Expected: PASS (all subtests)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/limits.ts packages/proxy/test/limits.test.ts
git commit -m "feat(phase24): pure limits helpers — parsePositiveInt + byte-capped body reader (ADR-0037)"
```

---

### Task 2: Byte caps in NpmUpstream (tarball + packument + attestations)

**Files:**
- Modify: `packages/proxy/src/upstream.ts` — `NpmUpstream` constructor (lines 88-93), `getTarball` (line 148), `getPackument` (line 131), `getAttestations` (line 159)
- Test: `packages/proxy/test/tarball-size-e2e.test.ts`

**Interfaces:**
- Consumes: `readBodyCapped` from `./limits.js` (Task 1).
- Produces: `NpmUpstream` constructor becomes
  `constructor(registry = "https://registry.npmjs.org", tarballOrigins: readonly string[] = [], maxTarballBytes = 256 * 1024 * 1024, maxPackumentBytes = 128 * 1024 * 1024)`
  (Task 7 passes the env-configured caps as the 3rd/4th args). Over-cap ⇒ the read throws; `getTarball`/`getPackument` wrap it as `HttpError(502, …)`; `getAttestations` catches it and returns `null`.

- [ ] **Step 1: Write the failing test**

A hermetic local "registry" serving an oversized tarball and an oversized packument.

```typescript
// packages/proxy/test/tarball-size-e2e.test.ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, test } from "node:test";
import { NpmUpstream, HttpError } from "../src/upstream.js";

function listen(server: Server): Promise<string> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

describe("NpmUpstream byte caps (hermetic local registry)", () => {
  let registry: Server;
  let base = "";

  before(async () => {
    registry = createHttpServer((req, res) => {
      const url = req.url ?? "";
      // Packument for big-pkg: small JSON pointing tarball at the same origin.
      if (url === "/big-pkg") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({
          name: "big-pkg",
          versions: { "1.0.0": { name: "big-pkg", version: "1.0.0", dist: { tarball: `${base}/big-pkg/-/big-pkg-1.0.0.tgz` } } },
        }));
        return;
      }
      // Oversized tarball: 50 KB body, no content-length (chunked) so the cap must catch it mid-stream.
      if (url === "/big-pkg/-/big-pkg-1.0.0.tgz") {
        res.end(Buffer.alloc(50 * 1024, 9));
        return;
      }
      // Oversized packument for huge-doc: 50 KB JSON-ish body.
      if (url === "/huge-doc") {
        res.setHeader("content-type", "application/json");
        res.end(Buffer.alloc(50 * 1024, 0x20)); // spaces — irrelevant, cap trips before parse
        return;
      }
      res.statusCode = 404;
      res.end("{}");
    });
    base = await listen(registry);
  });
  after(() => registry.close());

  test("a tarball over the cap is refused with 502", async () => {
    const up = new NpmUpstream(base, [], 1024, 128 * 1024 * 1024); // 1 KB tarball cap
    await assert.rejects(
      () => up.getTarball("big-pkg", "1.0.0"),
      (err: unknown) => err instanceof HttpError && err.status === 502 && /too large/.test(err.message),
    );
  });

  test("a packument over the cap is refused with 502", async () => {
    const up = new NpmUpstream(base, [], 256 * 1024 * 1024, 1024); // 1 KB packument cap
    await assert.rejects(
      () => up.getPackument("huge-doc"),
      (err: unknown) => err instanceof HttpError && err.status === 502 && /too large/.test(err.message),
    );
  });

  test("a tarball under the cap fetches fine", async () => {
    const up = new NpmUpstream(base, [], 1024 * 1024, 128 * 1024 * 1024); // 1 MB tarball cap
    const buf = await up.getTarball("big-pkg", "1.0.0");
    assert.equal(buf.length, 50 * 1024);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/tarball-size-e2e.test.ts`
Expected: FAIL — the over-cap tarball/packument tests don't reject (unbounded `arrayBuffer()`/`json()`), and the constructor doesn't accept the cap args.

- [ ] **Step 3: Implement the caps**

In `packages/proxy/src/upstream.ts`, add the import near the top (after the existing `./net-config.js` import):

```typescript
import { readBodyCapped } from "./limits.js";
```

Replace the constructor (lines 88-93) with:

```typescript
  constructor(
    private readonly registry = "https://registry.npmjs.org",
    private readonly tarballOrigins: readonly string[] = [],
    private readonly maxTarballBytes = 256 * 1024 * 1024,
    private readonly maxPackumentBytes = 128 * 1024 * 1024,
  ) {
    this.registryOrigin = new URL(registry).origin;
  }
```

In `getPackument` (line 131), replace `const doc = (await res.json()) as PackumentDoc;` with:

```typescript
    const body = await readBodyCapped(res, this.maxPackumentBytes, `packument ${pkg}`)
      .catch((err) => { throw new HttpError(502, `upstream packument ${pkg}: ${(err as Error).message}`); });
    const doc = JSON.parse(body.toString("utf8")) as PackumentDoc;
```

In `getTarball` (line 148), replace `return Buffer.from(await res.arrayBuffer());` with:

```typescript
    return readBodyCapped(res, this.maxTarballBytes, `tarball ${pkg}@${version}`)
      .catch((err) => { throw new HttpError(502, `upstream tarball ${pkg}@${version}: ${(err as Error).message}`); });
```

In `getAttestations` (line 159), replace `return await res.json();` with:

```typescript
      const body = await readBodyCapped(res, this.maxPackumentBytes, `attestations ${pkg}@${version}`);
      return JSON.parse(body.toString("utf8"));
```

(The `getAttestations` body is already inside a `try { … } catch { return null; }` — an over-cap throw there is caught and becomes `null`, preserving the fail-open-to-"unknown" contract. Confirm the surrounding try/catch is intact after your edit.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/tarball-size-e2e.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Run the regression tests that exercise NpmUpstream + parsing**

Run: `node --import tsx --test packages/proxy/test/tarball-origin-e2e.test.ts packages/proxy/test/proxy.test.ts packages/proxy/test/audit-tree-e2e.test.ts`
Expected: PASS — `LocalFixtureUpstream` is untouched; `NpmUpstream`'s new params default to the large caps, so existing behavior is unchanged.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/upstream.ts packages/proxy/test/tarball-size-e2e.test.ts
git commit -m "feat(phase24): streamed byte caps for tarball + packument + attestations fetches (ADR-0037)"
```

---

### Task 3: Audit-tree dedupe + package cap

**Files:**
- Modify: `packages/proxy/src/server.ts` — `ServerOptions` (~line 78), `createServer` locals (~line 136), `/-/audit-tree` route (~lines 382-438)
- Test: `packages/proxy/test/audit-tree-limits-e2e.test.ts`

**Interfaces:**
- Consumes: nothing new at runtime (the number arrives via `ServerOptions`).
- Produces: `ServerOptions.maxTreePackages?: number` — Task 7 passes the env value; unset ⇒ default `5000`. Over-cap ⇒ **413**. Behavior: distinct `name@version` coordinates are audited once; the response has one row per requested coordinate in request order.

- [ ] **Step 1: Write the failing test**

`leftpad-lite@1.0.0` is a benign fixture package. This test counts upstream calls by wrapping `LocalFixtureUpstream`.

```typescript
// packages/proxy/test/audit-tree-limits-e2e.test.ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
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

/** LocalFixtureUpstream that counts getTarball calls, to prove dedupe. */
class CountingUpstream extends LocalFixtureUpstream {
  tarballCalls = 0;
  async getTarball(pkg: string, version: string) {
    this.tarballCalls++;
    return super.getTarball(pkg, version);
  }
}

function boot(upstream: LocalFixtureUpstream, maxTreePackages?: number): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream, store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), maxTreePackages,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

async function auditTree(base: string, packages: { name: string; version: string }[]): Promise<{ status: number; body: any }> {
  const res = await fetch(`${base}/-/audit-tree`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ packages }),
  });
  return { status: res.status, body: await res.json() };
}

describe("audit-tree dedupe + cap (ADR-0037)", () => {
  before(() => ensureFixtures());

  test("duplicate coordinates are audited once but returned per-request", async () => {
    const up = new CountingUpstream(FIXTURES);
    const { server, base } = await boot(up);
    try {
      const dupes = Array.from({ length: 5 }, () => ({ name: "leftpad-lite", version: "1.0.0" }));
      const { status, body } = await auditTree(base, dupes);
      assert.equal(status, 200);
      assert.equal(body.packages.length, 5, "one row per requested coordinate");
      assert.equal(up.tarballCalls, 1, "distinct coordinate audited exactly once");
    } finally { server.close(); }
  });

  test("over-cap distinct set returns 413 naming count and limit", async () => {
    const up = new LocalFixtureUpstream(FIXTURES);
    const { server, base } = await boot(up, 2); // cap = 2 distinct
    try {
      const pkgs = [
        { name: "leftpad-lite", version: "1.0.0" },
        { name: "leftpad-lite", version: "1.0.1" },
        { name: "leftpad-lite", version: "1.0.2" },
      ];
      const { status, body } = await auditTree(base, pkgs);
      assert.equal(status, 413);
      assert.match(body.error, /3.*(exceeds|limit).*2/);
    } finally { server.close(); }
  });

  test("duplicates collapse below the cap (5 dupes of 1 distinct, cap 2 → ok)", async () => {
    const up = new LocalFixtureUpstream(FIXTURES);
    const { server, base } = await boot(up, 2);
    try {
      const dupes = Array.from({ length: 5 }, () => ({ name: "leftpad-lite", version: "1.0.0" }));
      const { status } = await auditTree(base, dupes);
      assert.equal(status, 200, "5 dupes = 1 distinct, under the cap of 2");
    } finally { server.close(); }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/audit-tree-limits-e2e.test.ts`
Expected: FAIL — dupes cause 5 `getTarball` calls (no dedupe), and the over-cap case returns 200 (no cap).

- [ ] **Step 3: Implement dedupe + cap**

In `packages/proxy/src/server.ts`, add to `ServerOptions` (after `publicBaseUrl?` around line 78):

```typescript
  /** Max distinct packages per audit-tree request (ADR-0037). Undefined ⇒ 5000. */
  maxTreePackages?: number;
```

Add a local in `createServer` (beside `const publicBaseUrl = opts.publicBaseUrl;`):

```typescript
  const maxTreePackages = opts.maxTreePackages ?? 5000;
```

In the `/-/audit-tree` route, after the per-coordinate validation loop and before `const failOnError = …`, insert dedupe + cap:

```typescript
    // Dedupe by name@version before fanning out — auditVersion is deterministic,
    // so auditing a distinct coordinate once and re-expanding to per-request rows
    // is behavior-neutral (ADR-0037).
    const validCoords = coords as { name: string; version: string; integrity?: string }[];
    const distinctKeys: string[] = [];
    const distinctByKey = new Map<string, { name: string; version: string; integrity?: string }>();
    for (const co of validCoords) {
      const key = `${co.name}@${co.version}`;
      if (!distinctByKey.has(key)) { distinctByKey.set(key, co); distinctKeys.push(key); }
    }
    if (distinctKeys.length > maxTreePackages) {
      return res.status(413).json({
        error: `audit-tree request has ${distinctKeys.length} distinct packages, which exceeds the limit of ${maxTreePackages} (raise SENTINEL_MAX_TREE_PACKAGES)`,
      });
    }
```

Change the `mapPool` call to fan out over the **distinct** coordinates, capturing a per-key row map. Replace `const rows: TreePackageRow[] = await mapPool(coords as …, 8, async (co) => { … });` — i.e. change its first argument from `coords as { … }[]` to `distinctKeys.map((k) => distinctByKey.get(k)!)`, and assign the result to `distinctRows`:

```typescript
    const distinctRows: TreePackageRow[] = await mapPool(
      distinctKeys.map((k) => distinctByKey.get(k)!),
      8,
      async (co) => {
        // …existing row-building body, UNCHANGED…
      },
    );
```

Then replace the existing `rows.sort(…)` block with a re-expansion to per-request order (distinct rows are keyed back out; drop the alphabetical sort — request order is now the contract):

```typescript
    const rowByKey = new Map<string, TreePackageRow>();
    for (const row of distinctRows) rowByKey.set(`${row.name}@${row.version}`, row);
    const rows: TreePackageRow[] = validCoords.map((co) => rowByKey.get(`${co.name}@${co.version}`)!);
```

(Leave the `aggregate`/`result`/`res.json` lines below unchanged — they consume `rows`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/audit-tree-limits-e2e.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Run the audit-tree regression suites**

Run: `node --import tsx --test packages/proxy/test/audit-tree-e2e.test.ts packages/proxy/test/audit-tree-integrity-e2e.test.ts packages/proxy/test/tree.test.ts`
Expected: PASS. NOTE: if any existing test asserts the response rows are in **alphabetical** order, that assertion must change to **request order** — update it and note it in your report (the dedupe change intentionally makes row order match request order).

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/audit-tree-limits-e2e.test.ts
git commit -m "feat(phase24): audit-tree dedupe + SENTINEL_MAX_TREE_PACKAGES cap with 413 (ADR-0037)"
```

---

### Task 4: Request coalescing (stampede fix)

**Files:**
- Modify: `packages/proxy/src/server.ts` — `auditVersion` (lines 144-196)
- Test: `packages/proxy/test/coalesce-e2e.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: no signature change to `auditVersion`; internally, concurrent uncached public audits for the same `name@version` share one pipeline.

- [ ] **Step 1: Write the failing test**

Wraps `LocalFixtureUpstream` with a slow, counting `getTarball` so concurrent calls overlap.

```typescript
// packages/proxy/test/coalesce-e2e.test.ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { before, describe, test } from "node:test";
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

/** Slow, counting upstream: getTarball waits a tick so concurrent requests overlap. */
class SlowCountingUpstream extends LocalFixtureUpstream {
  tarballCalls = 0;
  async getTarball(pkg: string, version: string) {
    this.tarballCalls++;
    await new Promise((r) => setTimeout(r, 30));
    return super.getTarball(pkg, version);
  }
}

function boot(upstream: LocalFixtureUpstream): Promise<{ server: Server; base: string; upstream: LocalFixtureUpstream }> {
  const app = createServer({
    upstream, store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(),
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, upstream })); });
}

describe("request coalescing (ADR-0037)", () => {
  before(() => ensureFixtures());

  test("k concurrent uncached requests for one version share one getTarball", async () => {
    const up = new SlowCountingUpstream(FIXTURES);
    const { server, base } = await boot(up);
    try {
      const reqs = Array.from({ length: 6 }, () =>
        fetch(`${base}/-/audit/leftpad-lite/1.0.0`).then((r) => r.json() as Promise<AuditReport>));
      const reports = await Promise.all(reqs);
      // Baseline tarball fetch (previousVersion) may add calls for OTHER versions, but
      // leftpad-lite@1.0.0 itself must be fetched once across the 6 concurrent requests.
      const v100Calls = up.tarballCalls; // slow fixture has a single version, so this counts 1.0.0 fetches
      assert.ok(v100Calls <= 2, `expected coalesced fetch (<=2 incl. baseline), got ${v100Calls}`);
      assert.equal(new Set(reports.map((r) => r.verdict)).size, 1, "all requests see the same verdict");
    } finally { server.close(); }
  });
});
```

Note for the implementer: `/-/audit/:pkg/:version` is an existing read route that calls `auditVersion`. If the exact path differs in the codebase, use the route that maps to `auditVersion` for an uncached public package (grep for `auditVersion(` call sites). The assertion tolerates a baseline-version fetch; the point is that the **same** `name@version` is not fetched k times.

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/coalesce-e2e.test.ts`
Expected: FAIL — `tarballCalls` is ~6 (every concurrent request runs its own fetch before any populates the cache).

- [ ] **Step 3: Implement coalescing**

In `packages/proxy/src/server.ts`, refactor `auditVersion` (lines 144-196). Add an in-flight map as a `createServer` local (beside `maxTreePackages`):

```typescript
  // Transient concurrency dedupe: concurrent uncached public audits for the same
  // name@version share one pipeline. The integrity-keyed `store` stays the durable
  // cache (invariant #4); this map lives only within the overlapping-request window.
  const inFlight = new Map<string, Promise<{ report: AuditReport; tarball: Buffer }>>();
```

Split the current `auditVersion` body: keep the `isClaimed` private branch and the `providedTarball` fast path in `auditVersion`, and move the public uncached pipeline into an inner `auditPublicUncached`. Replace the whole function with:

```typescript
  /** Audit a specific version, using the verdict cache (integrity-keyed). */
  async function auditVersion(
    pkg: string,
    version: string,
    providedTarball?: Buffer,
  ): Promise<{ report: AuditReport; tarball: Buffer }> {
    // Claimed names are authoritative private — NEVER consult public upstream.
    if (isClaimed(pkg, enterprisePolicy)) {
      const cachedAudit = privateStore.getAudit(pkg, version);
      const tarball = privateStore.getTarball(pkg, version);
      if (!cachedAudit || !tarball) throw new HttpError(404, `private package not found ${pkg}@${version}`);
      const report = score(cachedAudit, enterprisePolicy, policyHash);
      store.put(report); // populate verdict store so /-/approvals can find the integrity
      return { report, tarball };
    }
    // A caller that already holds the bytes skips the fetch entirely — no coalescing needed.
    if (providedTarball) return auditPublicUncached(pkg, version, providedTarball);

    // Coalesce concurrent uncached fetches for the same coordinate.
    const key = `${pkg}@${version}`;
    const existing = inFlight.get(key);
    if (existing) return existing;
    const p = auditPublicUncached(pkg, version, undefined).finally(() => inFlight.delete(key));
    inFlight.set(key, p);
    return p;
  }

  async function auditPublicUncached(
    pkg: string,
    version: string,
    providedTarball: Buffer | undefined,
  ): Promise<{ report: AuditReport; tarball: Buffer }> {
    const pm = await upstream.getPackument(pkg);
    const vmeta = pm.versions[version];
    if (!vmeta) throw new HttpError(404, `unknown version ${pkg}@${version}`);

    const tarball = providedTarball ?? (await upstream.getTarball(pkg, version));
    const actualIntegrity = integrityOf(tarball);

    const cached = store.get(actualIntegrity);
    if (cached) return { report: cached.report, tarball };

    const prev = previousVersion(Object.keys(pm.versions), version);
    const baselineTarball = prev ? await upstream.getTarball(pkg, prev) : undefined;
    const attestations = vmeta.hasProvenance ? await upstream.getAttestations(pkg, version) : null;

    const meta: Omit<PackageMeta, "unpackedSize" | "fileCount" | "signature" | "provenance"> = {
      name: pkg,
      version,
      author: vmeta.author,
      maintainers: vmeta.maintainers,
      license: vmeta.license,
      hasInstallScripts: vmeta.hasInstallScripts,
      integrity: vmeta.integrity ?? actualIntegrity,
    };

    const releaseContext = buildReleaseContext(pm, version);
    const audit = await runAudit({
      meta, tarball, baselineTarball,
      signatures: vmeta.signatures, hasProvenance: vmeta.hasProvenance,
      attestations, signingKeys, trustMaterial: opts.trustMaterial,
      releaseContext, advisories, vulnerabilities,
    });
    const report = score(audit, enterprisePolicy, policyHash);
    store.put(report);
    return { report, tarball };
  }
```

(This preserves the exact pipeline — only the private branch and `providedTarball` path stay in `auditVersion`; everything from `getPackument` down moves verbatim into `auditPublicUncached`. Confirm `opts.trustMaterial` is still in scope — it is, both functions are nested in `createServer`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/coalesce-e2e.test.ts`
Expected: PASS (1 test)

- [ ] **Step 5: Run the core proxy regressions (auditVersion is on the gate + tree + explain paths)**

Run: `node --import tsx --test packages/proxy/test/proxy.test.ts packages/proxy/test/audit-tree-e2e.test.ts packages/proxy/test/explain-e2e.test.ts packages/proxy/test/private-serve.test.ts`
Expected: PASS — behavior is identical for sequential requests; only concurrent-dedupe changed.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/coalesce-e2e.test.ts
git commit -m "feat(phase24): coalesce concurrent uncached audits by name@version — stampede fix (ADR-0037)"
```

---

### Task 5: Token-bucket rate limiter (pure module)

**Files:**
- Create: `packages/proxy/src/rate-limit.ts`
- Test: `packages/proxy/test/rate-limit.test.ts`

**Interfaces:**
- Consumes: nothing (pure; clock injected).
- Produces (used by Task 6):
  - `interface RateLimiter { check(key: string): { allowed: boolean; retryAfterSec: number } }`
  - `createRateLimiter(opts: { rpm: number; now: () => number }): RateLimiter`

- [ ] **Step 1: Write the failing tests**

```typescript
// packages/proxy/test/rate-limit.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createRateLimiter } from "../src/rate-limit.js";

/** A mutable fake clock in milliseconds. */
function fakeClock(start = 0) {
  let t = start;
  return { now: () => t, advance: (ms: number) => { t += ms; } };
}

describe("createRateLimiter (token bucket)", () => {
  test("allows up to rpm requests in a window, then 429s", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 3, now: clock.now });
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, true);
    const denied = rl.check("a");
    assert.equal(denied.allowed, false);
    assert.ok(denied.retryAfterSec >= 1, "Retry-After is a positive number of seconds");
  });

  test("refills over time — after the window, requests are allowed again", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 2, now: clock.now });
    rl.check("a"); rl.check("a");
    assert.equal(rl.check("a").allowed, false);
    clock.advance(60_000); // one full minute → bucket refilled
    assert.equal(rl.check("a").allowed, true);
  });

  test("partial refill grants proportional tokens", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 60, now: clock.now }); // 1 token/sec
    for (let i = 0; i < 60; i++) rl.check("a");
    assert.equal(rl.check("a").allowed, false);
    clock.advance(1_000); // 1 second → ~1 token back
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, false);
  });

  test("distinct keys have independent buckets", () => {
    const clock = fakeClock();
    const rl = createRateLimiter({ rpm: 1, now: clock.now });
    assert.equal(rl.check("a").allowed, true);
    assert.equal(rl.check("a").allowed, false);
    assert.equal(rl.check("b").allowed, true, "key b is unaffected by key a");
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --import tsx --test packages/proxy/test/rate-limit.test.ts`
Expected: FAIL — `Cannot find module '../src/rate-limit.js'`

- [ ] **Step 3: Write the implementation**

```typescript
// packages/proxy/src/rate-limit.ts
/**
 * In-process token-bucket rate limiter (Phase 24, ADR-0037). Pure: the clock is
 * injected (deterministic tests, no wall-clock). One bucket per key; capacity =
 * rpm, refilling at rpm tokens per 60s. A lightweight sweep bounds the bucket
 * map under many distinct keys. This is a backstop — shared deployments should
 * still front the proxy with infra rate limiting.
 */

export interface RateLimiter {
  check(key: string): { allowed: boolean; retryAfterSec: number };
}

interface Bucket {
  tokens: number;
  last: number; // ms timestamp of the last refill
}

const WINDOW_MS = 60_000;
const MAX_TRACKED = 10_000; // sweep idle-full buckets once the map exceeds this

export function createRateLimiter(opts: { rpm: number; now: () => number }): RateLimiter {
  const { rpm, now } = opts;
  const capacity = rpm;
  const refillPerMs = rpm / WINDOW_MS;
  const buckets = new Map<string, Bucket>();

  function sweep(t: number): void {
    for (const [k, b] of buckets) {
      // A full bucket untouched for a full window is indistinguishable from a
      // never-seen key, so it is safe to drop.
      if (t - b.last >= WINDOW_MS && b.tokens >= capacity) buckets.delete(k);
    }
  }

  return {
    check(key: string) {
      const t = now();
      let b = buckets.get(key);
      if (!b) {
        if (buckets.size >= MAX_TRACKED) sweep(t);
        b = { tokens: capacity, last: t };
        buckets.set(key, b);
      } else {
        b.tokens = Math.min(capacity, b.tokens + (t - b.last) * refillPerMs);
        b.last = t;
      }
      if (b.tokens >= 1) {
        b.tokens -= 1;
        return { allowed: true, retryAfterSec: 0 };
      }
      const needed = 1 - b.tokens;
      const retryAfterSec = Math.max(1, Math.ceil(needed / refillPerMs / 1000));
      return { allowed: false, retryAfterSec };
    },
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --import tsx --test packages/proxy/test/rate-limit.test.ts`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/rate-limit.ts packages/proxy/test/rate-limit.test.ts
git commit -m "feat(phase24): pure token-bucket rate limiter with injectable clock (ADR-0037)"
```

---

### Task 6: Wire rate limiter into the server middleware

**Files:**
- Modify: `packages/proxy/src/server.ts` — imports, `ServerOptions` (~line 78), `createServer` (middleware gate + apply to 3 routes)
- Test: `packages/proxy/test/rate-limit-e2e.test.ts`

**Interfaces:**
- Consumes: `RateLimiter` from `./rate-limit.js` (Task 5).
- Produces: `ServerOptions.rateLimiter?: RateLimiter` — Task 7 constructs it from env with a real clock. Applied to `POST /-/audit-tree`, `GET /-/explain/*`, `POST /-/policy/preview` only; over-limit ⇒ 429 + `Retry-After`. Gate paths never limited.

- [ ] **Step 1: Write the failing test**

```typescript
// packages/proxy/test/rate-limit-e2e.test.ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { createRateLimiter } from "../src/rate-limit.js";
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

function boot(rpm?: number): Promise<{ server: Server; base: string }> {
  const rateLimiter = rpm ? createRateLimiter({ rpm, now: () => Date.now() }) : undefined;
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), rateLimiter,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, base: `http://127.0.0.1:${(s.address() as AddressInfo).port}` })); });
}

const auditTree = (base: string) => fetch(`${base}/-/audit-tree`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ packages: [{ name: "leftpad-lite", version: "1.0.0" }] }),
});

describe("rate limiting on expensive endpoints (ADR-0037)", () => {
  before(() => ensureFixtures());

  test("audit-tree 429s past the limit with Retry-After", async () => {
    const { server, base } = await boot(3);
    try {
      for (let i = 0; i < 3; i++) assert.equal((await auditTree(base)).status, 200);
      const limited = await auditTree(base);
      assert.equal(limited.status, 429);
      assert.ok(Number(limited.headers.get("retry-after")) >= 1);
    } finally { server.close(); }
  });

  test("no limiter ⇒ unlimited (no 429)", async () => {
    const { server, base } = await boot();
    try {
      for (let i = 0; i < 10; i++) assert.equal((await auditTree(base)).status, 200);
    } finally { server.close(); }
  });

  test("install-gate tarball path is never rate-limited", async () => {
    const { server, base } = await boot(1); // rpm=1: audit-tree would 429 on the 2nd call
    try {
      // Many tarball fetches must all succeed regardless of the tiny limit.
      for (let i = 0; i < 5; i++) {
        const res = await fetch(`${base}/leftpad-lite/-/leftpad-lite-1.0.0.tgz`);
        assert.equal(res.status, 200, "tarball gate path must not be rate-limited");
      }
    } finally { server.close(); }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/rate-limit-e2e.test.ts`
Expected: FAIL — `rateLimiter` isn't a `ServerOptions` field and no route enforces a limit, so the 4th audit-tree call returns 200 instead of 429.

- [ ] **Step 3: Implement the middleware gate**

In `packages/proxy/src/server.ts`:

Add the type import (with the other local imports near the top):

```typescript
import type { RateLimiter } from "./rate-limit.js";
```

Add to `ServerOptions` (after `maxTreePackages?` from Task 3):

```typescript
  /** Opt-in per-source rate limiter for expensive open endpoints (ADR-0037). Undefined ⇒ unlimited. */
  rateLimiter?: RateLimiter;
```

In `createServer`, after `const app = express();` and the json setup, define the gate (a no-op passthrough when disabled, so route wiring is uniform):

```typescript
  const rateLimiter = opts.rateLimiter;
  const rateGate: express.RequestHandler = rateLimiter
    ? (req, res, next) => {
        const key = req.socket.remoteAddress ?? "unknown";
        const { allowed, retryAfterSec } = rateLimiter.check(key);
        if (allowed) return next();
        res.setHeader("Retry-After", String(retryAfterSec));
        return res.status(429).json({ error: "rate limit exceeded — retry later or raise SENTINEL_RATE_LIMIT_RPM" });
      }
    : (_req, _res, next) => next();
```

Insert `rateGate` as the first handler on exactly these three route registrations (verified line numbers; locate by content). Each currently has the form `app.<verb>(<matcher>, async (req, res) => {…}` — add `rateGate` between the matcher and the handler:

- `app.post("/-/audit-tree", …)` (~line 382) → `app.post("/-/audit-tree", rateGate, async (req, res) => {…}`
- `app.post("/-/policy/preview", …)` (~line 344) → `app.post("/-/policy/preview", rateGate, (req, res) => {…}`
- `app.get(/^\/-\/explain\/(.+)\/([^/]+)$/, …)` (~line 292, a **regex** matcher) → `app.get(/^\/-\/explain\/(.+)\/([^/]+)$/, rateGate, async (req, res) => {…}`

Do NOT add `rateGate` to any tarball/packument/`/-/audit/…`/other route. (The `/-/audit/(.+)/([^/]+)` single-package read at ~line 256 is NOT rate-limited — only the three above.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/rate-limit-e2e.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Run the affected-route regressions**

Run: `node --import tsx --test packages/proxy/test/audit-tree-e2e.test.ts packages/proxy/test/explain-e2e.test.ts packages/proxy/test/policy-preview-e2e.test.ts`
Expected: PASS — with no `rateLimiter` passed, `rateGate` is a pure passthrough, so these are unaffected.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/rate-limit-e2e.test.ts
git commit -m "feat(phase24): rate-limit gate on audit-tree/explain/policy-preview (ADR-0037)"
```

---

### Task 7: Fail-closed env wiring in index.ts

**Files:**
- Modify: `packages/proxy/src/index.ts` — imports, `buildUpstream` (line 39), new resolvers, `main()` (line 166), `createServer({…})` call (line 163-area)
- Test: `packages/proxy/test/limits-startup.test.ts`

**Interfaces:**
- Consumes: `parsePositiveInt` from `./limits.js` (Task 1); `createRateLimiter` from `./rate-limit.js` (Task 5); `NpmUpstream(registry, tarballOrigins, maxTarballBytes, maxPackumentBytes)` (Task 2); `ServerOptions.maxTreePackages`/`.rateLimiter` (Tasks 3, 6).
- Produces: env contract — `SENTINEL_MAX_TREE_PACKAGES`, `SENTINEL_MAX_TARBALL_BYTES`, `SENTINEL_MAX_PACKUMENT_BYTES`, `SENTINEL_RATE_LIMIT_RPM`; each set-but-invalid ⇒ FATAL exit 1; unset ⇒ default (or disabled, for the rate limiter).

- [ ] **Step 1: Write the failing test**

```typescript
// packages/proxy/test/limits-startup.test.ts
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const execFileAsync = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const ENTRY = join(REPO_ROOT, "packages", "proxy", "src", "index.ts");
const FIXTURES = join(REPO_ROOT, "fixtures");
function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

describe("proxy boot with Phase 24 limit env vars (child process)", () => {
  ensureFixtures();
  const VARS = ["SENTINEL_MAX_TREE_PACKAGES", "SENTINEL_MAX_TARBALL_BYTES", "SENTINEL_MAX_PACKUMENT_BYTES", "SENTINEL_RATE_LIMIT_RPM"];

  function bootWith(extra: Record<string, string>): Promise<{ code: number; stderr: string }> {
    const env = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    for (const v of VARS) delete env[v];
    Object.assign(env, extra);
    return execFileAsync("npx", ["tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000 })
      .then(({ stderr }) => ({ code: 0, stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, stderr: String(err.stderr ?? "") }));
  }

  test("non-integer tree cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_TREE_PACKAGES: "lots" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("zero tarball cap → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_MAX_TARBALL_BYTES: "0" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("negative rate limit → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_RATE_LIMIT_RPM: "-5" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("valid values for all four → boots, exit 0", async () => {
    const { code } = await bootWith({
      SENTINEL_MAX_TREE_PACKAGES: "3000",
      SENTINEL_MAX_TARBALL_BYTES: "104857600",
      SENTINEL_MAX_PACKUMENT_BYTES: "52428800",
      SENTINEL_RATE_LIMIT_RPM: "120",
    });
    assert.equal(code, 0);
  });

  test("all unset → boots, exit 0 (zero behavior change)", async () => {
    const { code } = await bootWith({});
    assert.equal(code, 0);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/limits-startup.test.ts`
Expected: FAIL — the three invalid cases exit 0 (env vars ignored today).

- [ ] **Step 3: Implement the env wiring**

In `packages/proxy/src/index.ts`:

Add imports (beside the existing `./net-config.js` import):

```typescript
import { parsePositiveInt } from "./limits.js";
import { createRateLimiter, type RateLimiter } from "./rate-limit.js";
```

Add a small helper beside the other resolvers (after `resolvePublicBaseUrl`, ~line 153):

```typescript
/** Parse a positive-int env var, FATAL on invalid; undefined when unset. */
function resolvePositiveInt(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  try {
    return parsePositiveInt(raw, name);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}

function resolveRateLimiter(): RateLimiter | undefined {
  const rpm = resolvePositiveInt("SENTINEL_RATE_LIMIT_RPM");
  if (rpm === undefined) return undefined;
  return createRateLimiter({ rpm, now: () => Date.now() });
}
```

Change `buildUpstream` (line 39) to thread the byte caps into `NpmUpstream`. Its current tail is `return new NpmUpstream(env("SENTINEL_REGISTRY", …), tarballOrigins);` — change the signature and that line:

```typescript
function buildUpstream(
  tarballOrigins: readonly string[],
  maxTarballBytes: number | undefined,
  maxPackumentBytes: number | undefined,
): Upstream {
  const mode = env("SENTINEL_UPSTREAM", "npm");
  if (mode === "fixtures" || mode.startsWith("fixtures:")) {
    const dir = mode.includes(":")
      ? resolve(mode.split(":")[1] ?? "")
      : resolve(env("SENTINEL_FIXTURES", "fixtures"));
    return new LocalFixtureUpstream(dir);
  }
  return new NpmUpstream(
    env("SENTINEL_REGISTRY", "https://registry.npmjs.org"),
    tarballOrigins,
    maxTarballBytes ?? 256 * 1024 * 1024,
    maxPackumentBytes ?? 128 * 1024 * 1024,
  );
}
```

In `main()`: where `const tarballOrigins = …; const publicBaseUrl = …; const upstream = buildUpstream(tarballOrigins);` are set (Phase 23 wiring), update to:

```typescript
  const tarballOrigins = resolveTarballOrigins();
  const publicBaseUrl = resolvePublicBaseUrl();
  const maxTarballBytes = resolvePositiveInt("SENTINEL_MAX_TARBALL_BYTES");
  const maxPackumentBytes = resolvePositiveInt("SENTINEL_MAX_PACKUMENT_BYTES");
  const maxTreePackages = resolvePositiveInt("SENTINEL_MAX_TREE_PACKAGES");
  const rateLimiter = resolveRateLimiter();
  const upstream = buildUpstream(tarballOrigins, maxTarballBytes, maxPackumentBytes);
```

Add `maxTreePackages` and `rateLimiter` to the `createServer({ … })` options object.

Add startup log lines beside the Phase 23 ones:

```typescript
    console.log(`  limits   : tree ${maxTreePackages ?? 5000} pkgs, tarball ${(maxTarballBytes ?? 256 * 1024 * 1024)} B, packument ${(maxPackumentBytes ?? 128 * 1024 * 1024)} B`);
    console.log(`  rate-limit: ${rateLimiter ? `${process.env.SENTINEL_RATE_LIMIT_RPM} rpm/source` : "disabled"}`);
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/limits-startup.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/index.ts packages/proxy/test/limits-startup.test.ts
git commit -m "feat(phase24): fail-closed startup wiring for tree/byte caps + rate limiter (ADR-0037)"
```

---

### Task 8: ADR-0037 + docs + full gate

**Files:**
- Create: `docs/adr/0037-resource-robustness.md`
- Modify: `docs/adr/README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, `README.md`

**Interfaces:**
- Consumes: everything above (document the shipped behavior — write from the actual code).
- Produces: the merged phase's documentation trail.

- [ ] **Step 1: Write ADR-0037**

```markdown
# ADR-0037: Resource robustness — caps, coalescing, and opt-in rate limiting

Date: 2026-07-09
Status: Accepted

## Context

An external security audit flagged that several open endpoints and upstream
fetches can be driven to do unbounded expensive work: `/-/audit-tree` accepts
arbitrarily many coordinates and fans out audits, each of which fully buffers a
tarball (and packument/attestations) in memory; concurrent uncached requests
for the same package each run the whole fetch/extract/score pipeline (cache
stampede); and no in-process throttle protects the expensive read endpoints.

## Decision

Four bounded-work changes, all under this ADR:

1. **Audit-tree caps + dedupe.** `/-/audit-tree` dedupes coordinates by
   `name@version` before fan-out (deterministic audit ⇒ behavior-neutral),
   audits each distinct coordinate once, and re-expands rows to one per
   requested coordinate in request order. If the distinct count exceeds
   `SENTINEL_MAX_TREE_PACKAGES` (default 5000), it returns 413 — no silent
   truncation.
2. **Streamed byte caps.** A shared byte-counting reader replaces unbounded
   `arrayBuffer()`/`json()` reads in `NpmUpstream`: it rejects up front if
   content-length exceeds the cap and aborts mid-stream if the running total
   does. `SENTINEL_MAX_TARBALL_BYTES` (default 256 MB) bounds tarballs;
   `SENTINEL_MAX_PACKUMENT_BYTES` (default 128 MB, a deliberately generous DoS
   backstop) bounds packument/attestations. Over-cap is a 502 (or a null
   attestation, preserving fail-open).
3. **Request coalescing.** An in-flight `name@version` map lets concurrent
   uncached public audits share one pipeline; the entry clears on settle so a
   failure isn't cached. The integrity hash stays the durable cache key
   (invariant #4); the map is transient concurrency dedupe only.
4. **Opt-in rate limiting.** A pure in-house token bucket (injectable clock,
   keyed by socket remote address) throttles `POST /-/audit-tree`,
   `GET /-/explain/*`, and `POST /-/policy/preview` when
   `SENTINEL_RATE_LIMIT_RPM` is set; over-limit ⇒ 429 + Retry-After. The
   install-gate paths are never limited — coalescing and the integrity cache
   already make them cheap, and throttling installs would break the
   transparent-proxy promise.

All four env vars parse fail-closed at startup (malformed ⇒ FATAL).

## Alternatives considered

- **Auth on the expensive reads**: rejected — contradicts ADR-0025's
  reads-stay-open boundary. Rate limiting throttles without gating.
- **Truncate-and-warn oversized trees**: rejected — a silent under-audit reads
  as "clean"; the repo's no-silent-caps principle prefers a hard 413.
- **`express-rate-limit` dependency**: rejected — non-injectable clock (breaks
  deterministic tests) and store abstractions we don't need for a single-process
  in-memory limiter. A ~40-line token bucket keeps the zero-new-dep posture.
- **`X-Forwarded-For` keying**: rejected for now — spoofable without a
  trusted-proxy config; socket address is the safe default. An XFF-aware mode
  can come later.

## Consequences

- Memory per fetch is bounded by the byte caps; a hostile or accidental giant
  tarball is a 502, not an OOM.
- A monorepo whose distinct-package count exceeds the tree cap gets an
  actionable 413; the operator raises the env var.
- Shared network deployments should still front the proxy with infra rate
  limiting — the in-process limiter is a backstop, not a replacement.
- Scoring, caching semantics, and packument transparency are unchanged
  (invariants #1–#6).
```

- [ ] **Step 2: Update the doc set**

- `docs/adr/README.md`: append an ADR-0037 index entry matching the file's format (read it first).
- `ARCHITECTURE.md`: add a Phase 24 section (§3.24) where §3.23 sits, same style — the four changes, the four env vars, ADR-0037 reference.
- `CLAUDE.md`: add the Phase 24 paragraph after Phase 23's; mention the four env vars in the Stack & versions section beside the Phase 23 ones; update the test-count comment in Build/test/run with the real number from Step 3.
- `README.md`: add all four env vars to the env-var table (read the table first, match columns).

- [ ] **Step 3: Full gate**

Run: `npm run build`
Expected: clean.

Run: `npm test`
Expected: all green — the 580 baseline plus the new Phase 24 tests (limits ~11, tarball-size 3, audit-tree-limits 3, coalesce 1, rate-limit 4, rate-limit-e2e 3, limits-startup 5). Record the actual total for CLAUDE.md.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0037-resource-robustness.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase24): ADR-0037 resource robustness; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes

- **Spec coverage:** tree caps+dedupe (Task 3), streamed byte caps for tarball+packument+attestations (Tasks 1+2), request coalescing (Task 4), token-bucket rate limiting keyed by socket address with injectable clock (Tasks 5+6), fail-closed env wiring for all four vars (Task 7), ADR-0037 with all four rejected alternatives (Task 8). Every spec §1–§4 and the ADR/doc-impact section maps to a task.
- **Type consistency:** `parsePositiveInt(raw, name)` and `readBodyCapped(res, maxBytes, what)` (Task 1) match their call sites (Tasks 2, 7); `NpmUpstream(registry, tarballOrigins, maxTarballBytes, maxPackumentBytes)` matches between Tasks 2 and 7; `ServerOptions.maxTreePackages` matches Tasks 3 and 7; `RateLimiter`/`createRateLimiter({rpm, now})` matches Tasks 5, 6, 7; `ServerOptions.rateLimiter` matches Tasks 6 and 7.
- **Ordering risk noted:** Task 3 changes audit-tree row order from alphabetical to request order — Step 5 flags updating any existing test that asserts alphabetical order. Task 4 refactors `auditVersion`; the pipeline body is moved verbatim to preserve behavior.
- **Not in scope (Phase 25):** sandbox default-deny + directional path-cover (ADR-0038).
```


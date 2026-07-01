# Whole-tree lockfile audit (`sentinel audit-tree`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `sentinel audit-tree [lockfile]` — parse an npm lockfile, audit every resolved package through the proxy under the enterprise policy, roll the results into an aggregate verdict, and exit non-zero when the policy gate trips (the CI contract).

**Architecture:** Lockfile-format parsing lives in the CLI; it POSTs coordinates to a new proxy `POST /-/audit-tree` endpoint that fans out over the existing integrity-cached `auditVersion()` path and computes the aggregate + gate decision server-side (where the policy lives). No new scoring logic — pure composition. The aggregation and the `treeGate` threshold are pure, policy-driven functions in `@sentinel/core`.

**Tech Stack:** Node 24 + TypeScript (NodeNext, ESM, `.js` internal specifiers), Express 5, `commander` 15, tests on `node:test` + `tsx`.

## Global Constraints

- ESM only (`"type": "module"`); internal imports use `.js` specifiers even from `.ts`.
- **Determinism (invariant #1):** same lockfile + same policy ⇒ same aggregate verdict and same sorted output, independent of fan-out order.
- **Gate threshold is policy data, not code (invariant #1):** the trip level is the `treeGate` field on `EnterprisePolicy`, default `"block"`. No hardcoded verdict comparison in a code path.
- **Sync gate stays cheap (invariant #3):** `/-/audit-tree` is an explicit `/-/` batch endpoint, never on the tarball request path.
- **Fail open per package (invariant #6):** one unresolvable package becomes an `error` row; it must not crash the run.
- **Full-mode per package:** we audit a pinned set; the ADR-0008 diff multiplier does not apply (this falls out of using `auditVersion`, which only diffs against a previous version during a tarball fetch — the tree path calls it the same way `/-/audit` does).
- **Hermetic tests (CLAUDE.md):** `LocalFixtureUpstream` only, never live npm. Synthetic-malicious fixtures are scored as text, never executed.
- **`Verdict` is exactly `"allow" | "warn" | "block"`** — there is no `observe` verdict (`observe` is a proxy *mode*).
- Build with `npm run build`; if `rm` of `dist/` fails EPERM, use `npx tsc --build --force <pkg>`.
- Run a single test file: `node --import tsx --test <path>`. Full suite: `npm test`.

---

### Task 1: `treeGate` policy field + `treeGateOf` helper

**Files:**
- Modify: `packages/core/src/policy.ts` (interface, `DEFAULT_POLICY`, `parsePolicy` validation + return, new `treeGateOf`)
- Modify: `packages/core/src/index.ts` (export `treeGateOf`)
- Test: `packages/core/test/policy.test.ts`

**Interfaces:**
- Consumes: `EnterprisePolicy`, `DEFAULT_POLICY`, `parsePolicy` (existing); `Verdict` from `./types.js`.
- Produces: `EnterprisePolicy.treeGate?: Verdict`; `treeGateOf(policy: EnterprisePolicy): Verdict` (returns `policy.treeGate ?? "block"`).

- [ ] **Step 1: Write the failing test**

Add to `packages/core/test/policy.test.ts`. First extend the import from `../src/policy.js` (or `@sentinel/core`) to include `treeGateOf` and `parsePolicy`/`DEFAULT_POLICY` if not already imported, then add:

```ts
import { DEFAULT_POLICY, parsePolicy, treeGateOf } from "../src/policy.js";

describe("treeGate policy field", () => {
  test("treeGateOf defaults to block and honors an explicit value", () => {
    assert.equal(treeGateOf(DEFAULT_POLICY), "block");
    assert.equal(treeGateOf({ ...DEFAULT_POLICY, treeGate: "warn" }), "warn");
    assert.equal(treeGateOf({ ...DEFAULT_POLICY, treeGate: undefined }), "block");
  });

  test("parsePolicy accepts a valid treeGate and rejects a bad one", () => {
    const good = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, treeGate: "warn" }));
    assert.equal(parsePolicy(good).treeGate, "warn");
    const bad = Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, treeGate: "nope" }));
    assert.throws(() => parsePolicy(bad), /treeGate/);
  });
});
```

> Note: `../src/policy.js` may already be imported in this file — merge names into the existing import rather than adding a duplicate line.

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/core/test/policy.test.ts`
Expected: FAIL — `treeGateOf` is not exported / not a function.

- [ ] **Step 3: Write minimal implementation**

In `packages/core/src/policy.ts`:

1. Extend the type import at the top:
```ts
import type { Severity, Verdict } from "./types.js";
```

2. Add the optional field to the interface, right after `privateNamespaces: string[];`:
```ts
  /** Verdict level at which a whole-tree audit trips the gate (ADR-0020). Default "block". */
  treeGate?: Verdict;
```

3. Add `treeGate: "block"` to `DEFAULT_POLICY`, after `privateNamespaces: []`:
```ts
  privateNamespaces: [],
  treeGate: "block",
```

4. Add a verdict allow-list constant next to `SEVERITIES`:
```ts
const VERDICTS: readonly string[] = ["allow", "warn", "block"];
```

5. In `parsePolicy`, after the `privateNamespaces` validation block and before `return {`:
```ts
  // Validate treeGate if present.
  if (p.treeGate !== undefined && !VERDICTS.includes(p.treeGate as string)) {
    throw new Error(`invalid policy: treeGate must be one of ${VERDICTS.join(", ")} (got "${p.treeGate}")`);
  }
```

6. Add `treeGate` to the `parsePolicy` return object, after `privateNamespaces: p.privateNamespaces ?? [],`:
```ts
    ...(p.treeGate !== undefined ? { treeGate: p.treeGate as Verdict } : {}),
```

7. Add the helper at the end of the file:
```ts
/** The verdict level at which `audit-tree` gates. Policy data, default "block". */
export function treeGateOf(policy: EnterprisePolicy): Verdict {
  return policy.treeGate ?? "block";
}
```

In `packages/core/src/index.ts`, add `treeGateOf` to the existing `./policy.js` export block:
```ts
  parsePolicy,
  loadPolicy,
  treeGateOf,
  type EnterprisePolicy,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --import tsx --test packages/core/test/policy.test.ts`
Expected: PASS (all tests in the file, including pre-existing ones).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/policy.ts packages/core/src/index.ts packages/core/test/policy.test.ts
git commit -m "feat(core): treeGate policy field + treeGateOf (ADR-0020 gate threshold as data)"
```

---

### Task 2: `aggregateTree` + tree types in `@sentinel/core`

**Files:**
- Create: `packages/core/src/tree.ts`
- Modify: `packages/core/src/index.ts` (export the new symbols)
- Test: `packages/core/test/tree.test.ts`

**Interfaces:**
- Consumes: `Verdict` from `./types.js`.
- Produces:
  - `type TreeStatus = Verdict | "error"`
  - `interface TreePackageRow { name: string; version: string; status: TreeStatus; score: number | null; topFinding: string | null; error: string | null; }`
  - `interface TreeAggregate { verdict: Verdict; gated: boolean; counts: { allow: number; warn: number; block: number; error: number }; }`
  - `interface TreeAuditResult { aggregate: TreeAggregate; packages: TreePackageRow[]; }`
  - `function aggregateTree(rows: TreePackageRow[], treeGate: Verdict): TreeAggregate`

- [ ] **Step 1: Write the failing test**

Create `packages/core/test/tree.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { aggregateTree, type TreePackageRow } from "../src/tree.js";

function row(status: TreePackageRow["status"]): TreePackageRow {
  return { name: "p", version: "1.0.0", status, score: null, topFinding: null, error: null };
}

describe("aggregateTree", () => {
  test("worst-case-wins verdict and counts", () => {
    const a = aggregateTree([row("allow"), row("warn"), row("block"), row("allow")], "block");
    assert.equal(a.verdict, "block");
    assert.deepEqual(a.counts, { allow: 2, warn: 1, block: 1, error: 0 });
    assert.equal(a.gated, true);
  });

  test("gates at the treeGate level", () => {
    const warnTree = [row("allow"), row("warn")];
    assert.equal(aggregateTree(warnTree, "block").gated, false); // worst=warn, gate=block
    assert.equal(aggregateTree(warnTree, "warn").gated, true);   // worst=warn, gate=warn
  });

  test("error rows are counted but never set the verdict or the gate", () => {
    const a = aggregateTree([row("allow"), row("error"), row("error")], "block");
    assert.equal(a.verdict, "allow");
    assert.equal(a.gated, false);
    assert.equal(a.counts.error, 2);
  });

  test("empty tree is allow / not gated", () => {
    const a = aggregateTree([], "block");
    assert.equal(a.verdict, "allow");
    assert.equal(a.gated, false);
  });

  test("aggregate is order-independent", () => {
    const rows = [row("block"), row("allow"), row("warn")];
    const forward = aggregateTree(rows, "block");
    const reversed = aggregateTree([...rows].reverse(), "block");
    assert.deepEqual(forward, reversed);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/core/test/tree.test.ts`
Expected: FAIL — cannot find module `../src/tree.js`.

- [ ] **Step 3: Write minimal implementation**

Create `packages/core/src/tree.ts`:

```ts
import type { Verdict } from "./types.js";

export type TreeStatus = Verdict | "error";

/** One package's line in a whole-tree audit. Compact by design — a gate summary
 *  needs the verdict, not the full report. */
export interface TreePackageRow {
  name: string;
  version: string;
  status: TreeStatus;
  score: number | null;
  topFinding: string | null;
  error: string | null;
}

export interface TreeAggregate {
  verdict: Verdict;
  gated: boolean;
  counts: { allow: number; warn: number; block: number; error: number };
}

export interface TreeAuditResult {
  aggregate: TreeAggregate;
  packages: TreePackageRow[];
}

const VERDICT_RANK: Record<Verdict, number> = { allow: 0, warn: 1, block: 2 };
const RANK_VERDICT: Verdict[] = ["allow", "warn", "block"];

/**
 * Roll per-package rows into one verdict. Worst-case-wins over non-error rows,
 * order-independent (invariant #1). `error` rows are counted but never set the
 * aggregate verdict or trip the gate (invariant #6). `gated` is true when the
 * worst verdict is at or above the policy's {@link Verdict} `treeGate`.
 */
export function aggregateTree(rows: TreePackageRow[], treeGate: Verdict): TreeAggregate {
  const counts = { allow: 0, warn: 0, block: 0, error: 0 };
  let worst = 0; // defaults to "allow" when there are no non-error rows
  for (const r of rows) {
    counts[r.status]++;
    if (r.status !== "error") worst = Math.max(worst, VERDICT_RANK[r.status]);
  }
  const verdict = RANK_VERDICT[worst]!;
  const gated = worst >= VERDICT_RANK[treeGate];
  return { verdict, gated, counts };
}
```

In `packages/core/src/index.ts`, add a new export block (after the policy block is fine):
```ts
export {
  aggregateTree,
  type TreeStatus,
  type TreePackageRow,
  type TreeAggregate,
  type TreeAuditResult,
} from "./tree.js";
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --import tsx --test packages/core/test/tree.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/tree.ts packages/core/src/index.ts packages/core/test/tree.test.ts
git commit -m "feat(core): aggregateTree + tree types (worst-case-wins, order-independent)"
```

---

### Task 3: Proxy `POST /-/audit-tree` endpoint

**Files:**
- Modify: `packages/proxy/src/server.ts` (imports, a `mapPool` helper, the route)
- Test: `packages/proxy/test/tree.test.ts`

**Interfaces:**
- Consumes: `auditVersion(pkg, version)` (existing closure returning `{ report, tarball }`); `aggregateTree`, `treeGateOf`, `type TreePackageRow`, `type TreeAuditResult` from `@sentinel/core`.
- Produces: `POST /-/audit-tree` accepting `{ packages: [{ name: string; version: string; integrity?: string }] }` and returning `TreeAuditResult` JSON (`packages` sorted by `name@version`).

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/tree.test.ts` (mirrors the harness in `proxy.test.ts`):

```ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type TreeAuditResult } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

async function auditTree(base: string, packages: { name: string; version: string }[]): Promise<TreeAuditResult> {
  const res = await fetch(`${base}/-/audit-tree`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ packages }),
  });
  assert.ok(res.ok, `expected 2xx, got ${res.status}`);
  return (await res.json()) as TreeAuditResult;
}

describe("POST /-/audit-tree (local fixtures)", () => {
  let server: Server;
  let base: string;

  before(async () => {
    ensureFixtures();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(),
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; resolve(); });
    });
  });
  after(() => server?.close());

  test("a benign tree is allow / not gated", async () => {
    const r = await auditTree(base, [
      { name: "leftpad-lite", version: "1.0.0" },
      { name: "net-fetch-lite", version: "1.0.0" },
    ]);
    assert.equal(r.aggregate.verdict, "allow");
    assert.equal(r.aggregate.gated, false);
    assert.equal(r.packages.length, 2);
  });

  test("a tree containing the malicious fixture is block / gated and names it", async () => {
    const r = await auditTree(base, [
      { name: "leftpad-lite", version: "1.0.0" },
      { name: "color-stream", version: "1.4.1" },
    ]);
    assert.equal(r.aggregate.verdict, "block");
    assert.equal(r.aggregate.gated, true);
    const cs = r.packages.find((p) => p.name === "color-stream");
    assert.equal(cs?.status, "block");
  });

  test("an unresolvable package is an error row, not a crash", async () => {
    const r = await auditTree(base, [
      { name: "leftpad-lite", version: "1.0.0" },
      { name: "does-not-exist", version: "9.9.9" },
    ]);
    const miss = r.packages.find((p) => p.name === "does-not-exist");
    assert.equal(miss?.status, "error");
    assert.ok(miss?.error);
    assert.equal(r.aggregate.counts.error, 1);
    assert.equal(r.aggregate.gated, false); // errors never gate
  });

  test("output is deterministic and sorted by name@version", async () => {
    const coords = [
      { name: "net-fetch-lite", version: "1.0.0" },
      { name: "leftpad-lite", version: "1.0.0" },
    ];
    const a = await auditTree(base, coords);
    const b = await auditTree(base, [...coords].reverse());
    assert.deepEqual(a, b);
    assert.deepEqual(a.packages.map((p) => p.name), ["leftpad-lite", "net-fetch-lite"]);
  });

  test("a malformed body is a 400", async () => {
    const res = await fetch(`${base}/-/audit-tree`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ nope: 1 }),
    });
    assert.equal(res.status, 400);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/tree.test.ts`
Expected: FAIL — `/-/audit-tree` returns 404 (`assert.ok(res.ok)` fails).

- [ ] **Step 3: Write minimal implementation**

In `packages/proxy/src/server.ts`:

1. Extend the `@sentinel/core` import block to add:
```ts
  aggregateTree,
  treeGateOf,
  type TreePackageRow,
  type TreeAuditResult,
```

2. Add a bounded-concurrency helper near the top of the file (module scope, after the imports and `TARBALL_RE`):
```ts
/** Run `fn` over `items` with at most `limit` in flight; preserves input order. */
async function mapPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
```

3. Register the route alongside the other `/-/` routes (e.g. right after the `app.get("/-/audits", ...)` block). `express.json()` is already applied to non-PUT requests, so `req.body` is parsed:
```ts
  // Whole-tree audit: fan out over the integrity-cached auditVersion path and
  // roll up a policy-gated aggregate (ADR-0020). Batch endpoint, not the gate path.
  app.post("/-/audit-tree", async (req, res) => {
    const body = req.body as { packages?: unknown };
    if (!body || !Array.isArray(body.packages)) {
      return res.status(400).json({ error: "expected { packages: [{ name, version }] }" });
    }
    const coords = body.packages as { name?: unknown; version?: unknown }[];
    for (const cc of coords) {
      if (!cc || typeof cc.name !== "string" || typeof cc.version !== "string") {
        return res.status(400).json({ error: "each package needs a string name and version" });
      }
    }
    const rows: TreePackageRow[] = await mapPool(
      coords as { name: string; version: string }[],
      8,
      async (co) => {
        try {
          const { report } = await auditVersion(co.name, co.version);
          return {
            name: co.name, version: co.version, status: report.verdict,
            score: report.score, topFinding: report.findings[0]?.message ?? null, error: null,
          };
        } catch (err) {
          return {
            name: co.name, version: co.version, status: "error" as const,
            score: null, topFinding: null, error: (err as Error)?.message ?? "audit failed",
          };
        }
      },
    );
    rows.sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
    const aggregate = aggregateTree(rows, treeGateOf(enterprisePolicy));
    const result: TreeAuditResult = { aggregate, packages: rows };
    res.json(result);
  });
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/tree.test.ts`
Expected: PASS (5 tests).

> If the malicious-tree test reports `color-stream` as `warn`/`allow` instead of `block`, do not weaken the assertion — confirm the fixture still scores block via `node --import tsx --test packages/proxy/test/proxy.test.ts` (the block-policy suite) and re-run fixtures with `npm run fixtures`. A drifting fixture is the likely cause (see memory: fixture tarball staleness).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/tree.test.ts
git commit -m "feat(proxy): POST /-/audit-tree — fan-out + server-side policy-gated aggregate"
```

---

### Task 4: CLI lockfile parser

**Files:**
- Create: `packages/cli/src/lockfile.ts`
- Test: `packages/cli/test/lockfile.test.ts`

**Interfaces:**
- Produces:
  - `interface Coordinate { name: string; version: string; integrity?: string }`
  - `function parseLockfile(raw: string, opts?: { omitDev?: boolean }): Coordinate[]` — parses an npm `package-lock.json` v2/v3 `packages` map into deduped, `name@version`-sorted registry coordinates; skips the root `""` entry, `link:`/`file:` entries, and (when `omitDev`) dev deps.

- [ ] **Step 1: Write the failing test**

Create `packages/cli/test/lockfile.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parseLockfile } from "../src/lockfile.js";

const LOCK = JSON.stringify({
  name: "root", version: "1.0.0", lockfileVersion: 3,
  packages: {
    "": { name: "root", version: "1.0.0" },
    "node_modules/leftpad-lite": { version: "1.0.0", resolved: "https://r/leftpad-lite/-/leftpad-lite-1.0.0.tgz", integrity: "sha512-A" },
    "node_modules/net-fetch-lite": { version: "1.0.0", resolved: "https://r/net-fetch-lite/-/x.tgz", integrity: "sha512-B" },
    "node_modules/@scope/pkg": { version: "2.0.0", resolved: "https://r/@scope/pkg/-/x.tgz" },
    "node_modules/tap": { version: "9.9.9", dev: true, resolved: "https://r/tap/-/x.tgz" },
    "node_modules/localdep": { version: "1.0.0", resolved: "file:../localdep" },
    "node_modules/linked": { version: "1.0.0", link: true },
    // duplicate coordinate at a nested path — must dedupe
    "node_modules/a/node_modules/leftpad-lite": { version: "1.0.0", resolved: "https://r/leftpad-lite/-/leftpad-lite-1.0.0.tgz", integrity: "sha512-A" },
  },
});

describe("parseLockfile", () => {
  test("extracts registry coordinates, deduped and sorted, skipping root/link/file", () => {
    const coords = parseLockfile(LOCK);
    assert.deepEqual(coords.map((c) => `${c.name}@${c.version}`), [
      "@scope/pkg@2.0.0", "leftpad-lite@1.0.0", "net-fetch-lite@1.0.0", "tap@9.9.9",
    ]);
    assert.equal(coords.find((c) => c.name === "leftpad-lite")?.integrity, "sha512-A");
  });

  test("omitDev drops dev-marked entries", () => {
    const coords = parseLockfile(LOCK, { omitDev: true });
    assert.equal(coords.find((c) => c.name === "tap"), undefined);
  });

  test("derives scoped names from the install path when name is absent", () => {
    const coords = parseLockfile(LOCK);
    assert.ok(coords.some((c) => c.name === "@scope/pkg" && c.version === "2.0.0"));
  });

  test("rejects a lockfile with no packages map", () => {
    assert.throws(() => parseLockfile(JSON.stringify({ dependencies: {} })), /packages/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/cli/test/lockfile.test.ts`
Expected: FAIL — cannot find module `../src/lockfile.js`.

- [ ] **Step 3: Write minimal implementation**

Create `packages/cli/src/lockfile.ts`:

```ts
export interface Coordinate {
  name: string;
  version: string;
  integrity?: string;
}

interface LockPackageEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  link?: boolean;
  dev?: boolean;
}

/**
 * Parse an npm `package-lock.json` (v2/v3) into deduped, `name@version`-sorted
 * registry coordinates. Lockfile-format knowledge lives here, not on the proxy.
 * Skips the root ("") entry, `link:`/`file:` entries, and (when `omitDev`) dev deps.
 */
export function parseLockfile(raw: string, opts: { omitDev?: boolean } = {}): Coordinate[] {
  const doc = JSON.parse(raw) as { packages?: Record<string, LockPackageEntry> };
  const packages = doc.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error("unsupported lockfile: expected a v2/v3 'packages' map (run `npm install` to regenerate)");
  }
  const byKey = new Map<string, Coordinate>();
  for (const [path, entry] of Object.entries(packages)) {
    if (path === "" || !entry || entry.link) continue;
    const resolved = entry.resolved ?? "";
    if (resolved.startsWith("file:") || resolved.startsWith("link:")) continue;
    if (opts.omitDev && entry.dev) continue;
    const name = entry.name ?? nameFromPath(path);
    if (!name || !entry.version) continue;
    const coord: Coordinate = { name, version: entry.version };
    if (entry.integrity) coord.integrity = entry.integrity;
    byKey.set(`${name}@${entry.version}`, coord);
  }
  return [...byKey.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

/** `node_modules/foo` -> `foo`; `node_modules/@scope/bar` -> `@scope/bar`. */
function nameFromPath(path: string): string {
  const marker = "node_modules/";
  const idx = path.lastIndexOf(marker);
  return idx >= 0 ? path.slice(idx + marker.length) : path;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --import tsx --test packages/cli/test/lockfile.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/lockfile.ts packages/cli/test/lockfile.test.ts
git commit -m "feat(cli): parseLockfile — npm v2/v3 lockfile -> deduped sorted coordinates"
```

---

### Task 5: CLI tree rendering + exit code

**Files:**
- Modify: `packages/cli/src/format.ts` (import tree types, add `formatTree` + `treeExitCode`)
- Test: `packages/cli/test/format-tree.test.ts`

**Interfaces:**
- Consumes: `TreeAuditResult` from `@sentinel/core`; existing `C`, `c`, `verdictColor` in `format.ts`.
- Produces: `formatTree(r: TreeAuditResult): string`; `treeExitCode(r: TreeAuditResult): number` (gated ⇒ `2`, else `0`).

- [ ] **Step 1: Write the failing test**

Create `packages/cli/test/format-tree.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { TreeAuditResult } from "@sentinel/core";
import { formatTree, treeExitCode } from "../src/format.js";

const gated: TreeAuditResult = {
  aggregate: { verdict: "block", gated: true, counts: { allow: 1, warn: 0, block: 1, error: 0 } },
  packages: [
    { name: "leftpad-lite", version: "1.0.0", status: "allow", score: 100, topFinding: null, error: null },
    { name: "color-stream", version: "1.4.1", status: "block", score: 10, topFinding: "exfiltrates env to network", error: null },
  ],
};
const clean: TreeAuditResult = {
  aggregate: { verdict: "allow", gated: false, counts: { allow: 1, warn: 0, block: 0, error: 0 } },
  packages: [{ name: "leftpad-lite", version: "1.0.0", status: "allow", score: 100, topFinding: null, error: null }],
};

describe("formatTree / treeExitCode", () => {
  test("renders each package, the summary line, and the aggregate verdict", () => {
    const out = formatTree(gated);
    assert.match(out, /leftpad-lite@1\.0\.0/);
    assert.match(out, /color-stream@1\.4\.1/);
    assert.match(out, /exfiltrates env to network/);
    assert.match(out, /1 allow · 0 warn · 1 block · 0 error/);
    assert.match(out, /BLOCK/);
    assert.match(out, /GATED/);
  });

  test("exit code is 2 when gated, 0 otherwise", () => {
    assert.equal(treeExitCode(gated), 2);
    assert.equal(treeExitCode(clean), 0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/cli/test/format-tree.test.ts`
Expected: FAIL — `formatTree` / `treeExitCode` not exported.

- [ ] **Step 3: Write minimal implementation**

In `packages/cli/src/format.ts`:

1. Extend the top type import to include the tree types:
```ts
import type { AuditReport, Capability, CapabilityKind, Severity, Verdict, TreeAuditResult } from "@sentinel/core";
```

2. Append at the end of the file:
```ts
const treeStatusColor: Record<string, string> = {
  allow: C.green, warn: C.yellow, block: C.red, error: C.gray,
};

/** Whole-tree audit summary: one line per package, then counts + aggregate verdict. */
export function formatTree(r: TreeAuditResult): string {
  const L: string[] = [];
  L.push("");
  L.push(c(C.bold, `  dependency tree audit (${r.packages.length} packages)`));
  L.push(c(C.gray, `  ${"─".repeat(56)}`));
  for (const p of r.packages) {
    const label = p.status.toUpperCase().padEnd(6);
    const score = p.score === null ? "" : c(C.gray, ` ${p.score}/100`);
    L.push(`  ${c(treeStatusColor[p.status] ?? C.gray, label)} ${p.name}@${p.version}${score}`);
    const note = p.error ?? p.topFinding;
    if (note) L.push(`         ${c(C.gray, note)}`);
  }
  const a = r.aggregate;
  L.push("");
  L.push(`  ${a.counts.allow} allow · ${a.counts.warn} warn · ${a.counts.block} block · ${a.counts.error} error`);
  L.push(
    `  verdict    ${c(C.bold + (verdictColor[a.verdict] ?? C.gray), a.verdict.toUpperCase())}` +
      (a.gated ? c(C.red, "  ✗ GATED") : c(C.green, "  ✓ ok")),
  );
  L.push("");
  return L.join("\n");
}

/** CI contract: non-zero when the tree is gated. */
export function treeExitCode(r: TreeAuditResult): number {
  return r.aggregate.gated ? 2 : 0;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --import tsx --test packages/cli/test/format-tree.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/format.ts packages/cli/test/format-tree.test.ts
git commit -m "feat(cli): formatTree + treeExitCode — tree summary rendering and CI exit code"
```

---

### Task 6: Wire the `audit-tree` command + end-to-end test

**Files:**
- Modify: `packages/cli/src/index.ts` (imports, the `audit-tree` command, a `fetchTree` helper)
- Test: `packages/proxy/test/audit-tree-e2e.test.ts`

**Interfaces:**
- Consumes: `parseLockfile`, `type Coordinate` from `./lockfile.js`; `formatTree`, `treeExitCode` from `./format.js`; `type TreeAuditResult` from `@sentinel/core`; existing `DEFAULT_PROXY`, `fail`, `readFileSync`.
- Produces: the `sentinel audit-tree [lockfile]` command (options `--proxy`, `--omit <type>`, `--json`); it reads the lockfile, parses coordinates, POSTs to `/-/audit-tree`, renders, and sets `process.exitCode` from `treeExitCode`.

- [ ] **Step 1: Write the failing end-to-end test**

Create `packages/proxy/test/audit-tree-e2e.test.ts`. It starts the proxy over fixtures, writes a temp lockfile referencing fixture packages, runs the real CLI via `tsx`, and asserts the exit code + output:

```ts
import assert from "node:assert/strict";
import { execFileSync, execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
const CLI_ENTRY = join(REPO_ROOT, "packages", "cli", "src", "index.ts");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs"))) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

function lockfile(pkgs: { name: string; version: string }[]): string {
  const packages: Record<string, unknown> = { "": { name: "proj", version: "1.0.0" } };
  for (const p of pkgs) {
    packages[`node_modules/${p.name}`] = { version: p.version, resolved: `https://registry/${p.name}/-/x.tgz` };
  }
  return JSON.stringify({ name: "proj", version: "1.0.0", lockfileVersion: 3, packages });
}

/**
 * Run the CLI via tsx; return { code, stdout } even on non-zero exit.
 * MUST be async: the proxy runs in THIS test process, so a synchronous child
 * (execFileSync) would block the event loop and deadlock the CLI's HTTP request
 * to the in-process proxy. `await` keeps the loop turning so the proxy can serve.
 */
async function runCli(args: string[]): Promise<{ code: number; stdout: string }> {
  try {
    const { stdout } = await execFileAsync(process.execPath, ["--import", "tsx", CLI_ENTRY, ...args], {
      cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, NO_COLOR: "1" },
    });
    return { code: 0, stdout };
  } catch (err) {
    // A non-zero exit rejects; the error carries the exit code and captured stdout.
    const e = err as { code?: number; stdout?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? "" };
  }
}

describe("sentinel audit-tree end-to-end", () => {
  let server: Server;
  let base: string;
  let dir: string;

  before(async () => {
    ensureFixtures();
    dir = mkdtempSync(join(tmpdir(), "sentinel-tree-"));
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(),
      approvals: new ApprovalStore(),
      enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(),
    });
    await new Promise<void>((resolve) => {
      server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; resolve(); });
    });
  });
  after(() => server?.close());

  test("a benign tree exits 0 and prints the allow verdict", async () => {
    const lock = join(dir, "benign-lock.json");
    writeFileSync(lock, lockfile([{ name: "leftpad-lite", version: "1.0.0" }, { name: "net-fetch-lite", version: "1.0.0" }]));
    const { code, stdout } = await runCli(["audit-tree", lock, "--proxy", base]);
    assert.equal(code, 0);
    assert.match(stdout, /ALLOW/);
  });

  test("a tree with the malicious fixture exits non-zero and prints GATED", async () => {
    const lock = join(dir, "mal-lock.json");
    writeFileSync(lock, lockfile([{ name: "leftpad-lite", version: "1.0.0" }, { name: "color-stream", version: "1.4.1" }]));
    const { code, stdout } = await runCli(["audit-tree", lock, "--proxy", base]);
    assert.equal(code, 2);
    assert.match(stdout, /GATED/);
    assert.match(stdout, /color-stream@1\.4\.1/);
  });

  test("--json emits the raw result", async () => {
    const lock = join(dir, "json-lock.json");
    writeFileSync(lock, lockfile([{ name: "leftpad-lite", version: "1.0.0" }]));
    const { stdout } = await runCli(["audit-tree", lock, "--proxy", base, "--json"]);
    const parsed = JSON.parse(stdout) as { aggregate: { verdict: string } };
    assert.equal(parsed.aggregate.verdict, "allow");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/audit-tree-e2e.test.ts`
Expected: FAIL — the CLI errors with `unknown command 'audit-tree'` (non-zero exit, no `ALLOW` in stdout).

- [ ] **Step 3: Write minimal implementation**

In `packages/cli/src/index.ts`:

1. Add imports. Extend the `@sentinel/core` import block with `type TreeAuditResult`, and add a new import for the lockfile parser and the format helpers:
```ts
import { formatReport, formatManifest, verdictExitCode, formatTree, treeExitCode, type Manifest } from "./format.js";
import { parseLockfile, type Coordinate } from "./lockfile.js";
```
(Also add `type TreeAuditResult` to the existing `from "@sentinel/core"` block.)

2. Register the command near the other `program.command(...)` definitions (e.g. right after the `scan` command):
```ts
program
  .command("audit-tree")
  .description("Audit every package in a resolved npm lockfile; exits non-zero when the tree is gated by policy.")
  .argument("[lockfile]", "path to package-lock.json", "package-lock.json")
  .option("-p, --proxy <url>", "Sentinel proxy base URL", DEFAULT_PROXY)
  .option("--omit <type>", "omit a dependency group (only 'dev' is supported)")
  .option("--json", "emit the raw JSON result", false)
  .action(async (lockfile: string, opts: { proxy: string; omit?: string; json: boolean }) => {
    try {
      const coords = parseLockfile(readFileSync(lockfile, "utf8"), { omitDev: opts.omit === "dev" });
      const result = await fetchTree(opts.proxy, coords);
      if (opts.json) console.log(JSON.stringify(result, null, 2));
      else console.log(formatTree(result));
      process.exitCode = treeExitCode(result);
    } catch (err) {
      fail(err, opts.proxy);
    }
  });
```

3. Add the fetch helper next to `fetchAudit`:
```ts
async function fetchTree(proxy: string, packages: Coordinate[]): Promise<TreeAuditResult> {
  const res = await fetch(`${proxy}/-/audit-tree`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ packages }),
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `tree audit failed: ${res.status}`);
  }
  return (await res.json()) as TreeAuditResult;
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --import tsx --test packages/proxy/test/audit-tree-e2e.test.ts`
Expected: PASS (3 tests).

Then confirm the whole suite and the build are green:

Run: `npm run build && npm test`
Expected: build clean; all tests pass (new count = previous + the tests added in Tasks 1–6). Note the new pass/skip totals for Task 7.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/proxy/test/audit-tree-e2e.test.ts
git commit -m "feat(cli): sentinel audit-tree command + end-to-end gate test"
```

---

### Task 7: Docs — ADR-0020, ARCHITECTURE, CLAUDE.md, README

**Files:**
- Create: `docs/adr/0020-whole-tree-lockfile-audit.md`
- Modify: `ARCHITECTURE.md` (new §3.8 + TOC line)
- Modify: `CLAUDE.md` (phase paragraph + test count)
- Modify: `README.md` (de-stale the Status section; mention `audit-tree`)

**Interfaces:** none (documentation only). Copy exact command/endpoint names from the implemented code: `sentinel audit-tree [lockfile]`, `POST /-/audit-tree`, `treeGate`, `aggregateTree`, `parseLockfile`.

- [ ] **Step 1: Write ADR-0020**

Create `docs/adr/0020-whole-tree-lockfile-audit.md`. Match the format of an existing ADR (open `docs/adr/0019-enforced-install-script-shell.md` for the exact heading structure). Content must cover:

```markdown
# ADR-0020: Whole-tree lockfile audit via proxy fan-out + server-side aggregate

## Status
Accepted (Phase 7).

## Context
Verdicts existed only per package — via `sentinel audit <pkg>` or as a side effect of
the proxy serving a tarball. There was no single-pass answer to a CI pipeline's question:
"is my whole resolved dependency tree acceptable under policy?" A malicious transitive
dependency was scored like any other tarball, but nothing rolled per-package verdicts into
one gate with a process exit code.

## Decision
Add `sentinel audit-tree [lockfile]`. The CLI parses the npm `package-lock.json` (v2/v3)
into registry coordinates (lockfile-format knowledge is a client concern) and POSTs them to
a new `POST /-/audit-tree` endpoint. The proxy fans out over the existing integrity-cached
`auditVersion()` path — reusing byte acquisition, the enterprise policy, and private-store
handling — and computes the aggregate + gate decision server-side, where the policy lives.

- **Bytes come from the proxy, not a local cache.** Rejected an offline/local-cache backend:
  it would re-implement byte acquisition + policy loading and diverge from the
  proxy-owns-the-store architecture. Proxy-backed composes with install (mostly cache hits).
- **Aggregation is worst-case-wins** (`block` ⊐ `warn` ⊐ `allow`), computed by pure,
  order-independent reduction (invariant #1).
- **The gate threshold is policy data:** a new `treeGate` field on `EnterprisePolicy`
  (default `"block"`), not a hardcoded verdict comparison.
- **Full-mode per package** — a pinned set, so the ADR-0008 diff multiplier does not apply.
- **Errors fail open per package** (invariant #6): an unresolvable dependency is a surfaced
  `error` row that never sets the aggregate verdict or trips the gate.

## Consequences
- CI gets a real gate: `sentinel audit-tree` exits non-zero on a gated tree.
- Requires a running proxy (consistent with `sentinel audit`).
- Deferred: CycloneDX SBOM output; lockfile-integrity-vs-served-integrity tamper detection;
  yarn/pnpm lockfiles; treating unresolved deps as a hard gate failure.
```

- [ ] **Step 2: Update ARCHITECTURE.md**

Add a TOC entry after the `### 3.7 Enforced install ...` line:
```markdown
### 3.8 Whole-tree audit (Phase 7, ADR-0020)
```

Add the matching section (place it after the §3.7 body, before `## 4`):
```markdown
### 3.8 Whole-tree audit (Phase 7, ADR-0020)

`sentinel audit-tree [lockfile]` audits an entire resolved dependency graph in one pass.
The CLI parses the npm `package-lock.json` (v2/v3) `packages` map into deduped, sorted
`{name, version, integrity?}` coordinates (skipping the root entry and `link:`/`file:`
deps) and POSTs them to `POST /-/audit-tree`. The proxy fans out with bounded concurrency
over the same integrity-cached `auditVersion()` path used by the tarball route, then rolls
the per-package verdicts into a worst-case-wins aggregate and a gate decision — both
computed server-side under the loaded policy. The gate trips at the policy's `treeGate`
level (default `block`); a gated tree makes the CLI exit non-zero (the CI contract).
Unresolvable packages become surfaced `error` rows and never trip the gate (invariant #6).
This is a `/-/` batch endpoint, never on the inline tarball request path (invariant #3).
```

- [ ] **Step 3: Update CLAUDE.md**

1. Add a Phase 7 line to the "What this is" section, after the Phase 6 paragraph:
```markdown
Phase 7 adds **`sentinel audit-tree`**: a whole-tree lockfile gate. It parses an npm
`package-lock.json`, audits every resolved package through the proxy (`POST /-/audit-tree`,
fan-out over the integrity cache), rolls a worst-case aggregate gated by the policy's
`treeGate` (default `block`), and exits non-zero on a gated tree (ADR-0020).
```

2. Update the test-count note in the `npm test` block. Run `npm test` first to get the exact numbers, then replace the count sentence with the observed darwin totals (and, if known, the Linux CI totals). Do not invent numbers — use what the suite reports.

- [ ] **Step 4: De-stale README.md**

The `## Status` section still says Phase 2 is "not yet implemented" — this is stale. Replace that paragraph with a brief current summary that lists the built phases through Phase 7 and mentions `sentinel audit-tree` as the whole-tree gate. Keep it short; ARCHITECTURE.md carries the detail.

- [ ] **Step 5: Verify docs build nothing and commit**

Run: `npm test`
Expected: still green (docs-only changes; confirms nothing regressed and gives the count used in Step 3).

```bash
git add docs/adr/0020-whole-tree-lockfile-audit.md ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase7): ADR-0020 whole-tree audit; ARCHITECTURE §3.8; CLAUDE phase + count; README de-stale"
```

---

## Self-Review

**Spec coverage:**
- §2.1 CLI command + lockfile parsing → Task 4 (`parseLockfile`) + Task 6 (command).
- §2.1 `--omit dev`, `--json`, `--proxy` → Task 4 (omitDev) + Task 6 (flags).
- §2.2 `POST /-/audit-tree` fan-out + server-side aggregate → Task 3.
- §3 worst-case-wins + `treeGate` as policy data + full-mode → Task 1 (treeGate) + Task 2 (aggregateTree).
- §4 per-package error rows, non-crashing → Task 2 (aggregate ignores errors) + Task 3 (endpoint catch + test).
- §5 output + exit code → Task 5 (`formatTree`, `treeExitCode`) + Task 6 (wiring).
- §6 hermetic tests (benign, malicious, determinism, errors, omit-dev, treeGate knob) → Tasks 1–3, 6 (treeGate-knob covered by the Task 2 unit test).
- §7 non-goals → not built (correct); recorded in ADR (Task 7).
- §8 ADR-0020 → Task 7.

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every test step shows the assertions. The only deferred value is the test *count* in Task 7 Step 3, which is intentionally read from `npm test` output rather than guessed.

**Type consistency:** `TreePackageRow`/`TreeAggregate`/`TreeAuditResult`/`aggregateTree` defined in Task 2 are used identically in Tasks 3, 5, 6. `treeGateOf` (Task 1) is consumed in Task 3. `Coordinate`/`parseLockfile` (Task 4) consumed in Task 6. `formatTree`/`treeExitCode` (Task 5) consumed in Task 6. `Verdict` is `allow|warn|block` throughout. Endpoint request shape `{ packages: [{name, version}] }` matches between Task 3 (server), the Task 3 test, and Task 6 (`fetchTree`).

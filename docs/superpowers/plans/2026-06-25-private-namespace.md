# Private-Namespace Registry — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Sentinel an authoritative private registry for enterprise-claimed namespaces — `npm publish` (audited + policy-gated, token-authed) stores private packages, and claimed names are served only from the private store, never from public npm (structurally eliminating dependency confusion).

**Architecture:** Claims live in the signed `EnterprisePolicy` (`privateNamespaces` globs). The proxy routes each request by `isClaimed(name)`: claimed → a new `PrivatePackageStore` (fail-closed, never public); not claimed → the existing transparent passthrough. A new `PUT /:pkg` write route (auth-before-parse, 64MB limit) audits/gates/stores publishes. Private installs reuse the existing score + 0011 approval gate.

**Tech Stack:** Node 24 (≥22), TypeScript (NodeNext, ESM, `.js` specifiers), Express 5, `node:crypto`, tests on `node:test` + `tsx`.

## Global Constraints

- ESM only; internal imports use `.js` specifiers even from `.ts` sources. No new runtime dependencies.
- **Fail-closed routing:** for a claimed name the proxy MUST NEVER consult the public upstream — not on a missing package/version, not on error. Claimed + unpublished ⇒ `404`.
- **Claims in the signed policy:** `privateNamespaces: string[]` on `EnterprisePolicy` (default `[]`), validated by `parsePolicy`. Empty ⇒ zero behavior change (pure passthrough). Reuse `matchPackage` for matching.
- **Publish auth before body parse:** the global `express.json({limit:"1mb"})` must NOT run on `PUT` (a base64 tarball exceeds 1MB and the global parser runs before the handler). Auth middleware (header-only) runs first; then a publish-route `express.json({limit:"64mb"})`. No token / wrong token / no configured tokens ⇒ `401`.
- **Publish is audited + policy-gated:** `runAudit` + `score(audit, enterprisePolicy, policyHash)`; `verdict==='block'` ⇒ reject, do not store.
- **Single-version PUT (captured fact):** each publish body carries exactly one new version; derive it from the single `_attachments` key (`<name>-<version>.tgz`). Scoped names arrive `%2f`-encoded — use regex routes + `decodeURIComponent` like the existing tarball/manifest routes.
- **Private installs use the same gate as public:** `score(policy)` + the 0011 capability/approval gate; header `x-sentinel-private: true`. Publish and approval are **orthogonal** (publishing does NOT auto-approve).
- **Telemetry:** local structured logging by default; the public-shadow probe is OFF by default (`SENTINEL_SHADOW_PROBE=1` to opt in) because it leaks claimed names to public npm.
- Determinism preserved; the malicious public fixture stays blocked; public passthrough unchanged for non-claimed names.
- Build with `npx tsc --build --force <pkg>` if `rm` of `dist/` fails with EPERM.

**Commands:** Build `npm run build` · Full suite `npm test` (a `pretest` hook rebuilds fixtures) · Single file `node --import tsx --test <file>` · Single test `--test-name-pattern "<name>"`.

---

## File structure

**Create:**
- `packages/proxy/src/private-store.ts` — `PrivatePackageStore` (byte + manifest + Audit storage, packument synthesis).
- `packages/proxy/src/private.ts` — pure helpers: `isClaimed`, `parsePublishBody`, `publishTokenValid`.
- `packages/proxy/test/private-store.test.ts`, `packages/proxy/test/private.test.ts`, `packages/proxy/test/publish.test.ts`, `packages/proxy/test/private-serve.test.ts`.
- `docs/adr/0015-private-registry-publish-protocol.md`.

**Modify:**
- `packages/core/src/policy.ts` — `privateNamespaces` on `EnterprisePolicy` + `DEFAULT_POLICY` + `parsePolicy`.
- `packages/core/test/policy.test.ts` — `privateNamespaces` validation tests.
- `packages/proxy/src/server.ts` — `ServerOptions` (privateStore + publishTokens); skip global json on PUT; the `PUT` publish route; claim-routing in the packument + tarball GET; the `gateAndSend` refactor; `GET /-/private`.
- `packages/proxy/src/index.ts` — build `PrivatePackageStore` + publish tokens from env; pass through.
- `packages/proxy/test/proxy.test.ts` — pass `privateStore` to existing `createServer` calls (new required option).
- `ARCHITECTURE.md`, `CLAUDE.md`, `docs/adr/0010-private-namespace-override.md`.

---

## Task 1: Core — `privateNamespaces` in the policy

**Files:**
- Modify: `packages/core/src/policy.ts`
- Test: `packages/core/test/policy.test.ts`

**Interfaces:**
- Produces: `EnterprisePolicy.privateNamespaces: string[]`; `DEFAULT_POLICY.privateNamespaces = []`; `parsePolicy` validates it (array of strings; absent ⇒ `[]`).

- [ ] **Step 1: Write the failing tests**

Append to `packages/core/test/policy.test.ts`:

```ts
import { parsePolicy as _pp } from "../src/index.js";
describe("privateNamespaces validation", () => {
  const valid = (over: object) => Buffer.from(JSON.stringify({ ...DEFAULT_POLICY, version: "v", ...over }));
  test("accepts an array of strings", () => {
    const p = _pp(valid({ privateNamespaces: ["@acme/*", "acme-config"] }));
    assert.deepEqual(p.privateNamespaces, ["@acme/*", "acme-config"]);
  });
  test("defaults to [] when absent", () => {
    const body = { ...DEFAULT_POLICY, version: "v" } as Record<string, unknown>;
    delete body.privateNamespaces;
    assert.deepEqual(_pp(Buffer.from(JSON.stringify(body))).privateNamespaces, []);
  });
  test("throws when present but not an array of strings", () => {
    assert.throws(() => _pp(valid({ privateNamespaces: "@acme/*" })));
    assert.throws(() => _pp(valid({ privateNamespaces: [1, 2] })));
  });
});
```

(`DEFAULT_POLICY` and `assert`/`describe`/`test` are already imported at the top of this file. If `parsePolicy` is already imported there, drop the extra import line and use the existing binding.)

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/core/test/policy.test.ts`
Expected: FAIL — `privateNamespaces` is `undefined` (not defaulted) / not validated.

- [ ] **Step 3: Implement**

In `packages/core/src/policy.ts`:

Add to the `EnterprisePolicy` interface (after `deny`):
```ts
  /** Names/scopes served authoritatively by the private registry (ADR-0010). */
  privateNamespaces: string[];
```

Add to `DEFAULT_POLICY` (after `deny: []`):
```ts
  privateNamespaces: [],
```

In `parsePolicy`, add a validation block before the final `return` (after the `deny` validation):
```ts
  if (p.privateNamespaces !== undefined) {
    if (!Array.isArray(p.privateNamespaces) || !p.privateNamespaces.every((x) => typeof x === "string")) {
      throw new Error("invalid policy: privateNamespaces must be an array of strings");
    }
  }
```

And include it in the returned object:
```ts
    deny: p.deny ?? [],
    privateNamespaces: p.privateNamespaces ?? [],
  };
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx tsc --build --force packages/core && node --import tsx --test packages/core/test/policy.test.ts`
Expected: PASS (and existing policy tests still green — `DEFAULT_POLICY` now has `privateNamespaces: []`, which the fixtures accept).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/policy.ts packages/core/test/policy.test.ts
git commit -m "feat(core): add privateNamespaces to EnterprisePolicy"
```

---

## Task 2: Proxy — `PrivatePackageStore`

**Files:**
- Create: `packages/proxy/src/private-store.ts`
- Test: `packages/proxy/test/private-store.test.ts`

**Interfaces:**
- Consumes: `type Audit` from `@sentinel/core`.
- Produces:
  - `interface StoredVersion { name; version; integrity; manifest: Record<string, unknown>; audit: Audit; actor: string; publishedAt: string }`
  - `interface PrivatePackument { name: string; "dist-tags": Record<string,string>; versions: Record<string, Record<string, unknown>> }`
  - `class PrivatePackageStore` with `constructor(dir?: string)`, `has(name): boolean`, `versions(name): string[]`, `getVersion(name, version): StoredVersion | undefined`, `getTarball(name, version): Buffer | undefined`, `getAudit(name, version): Audit | undefined`, `put(v: { name; version; integrity; manifest; tarball: Buffer; audit; actor }): StoredVersion`, `packument(name): PrivatePackument | undefined`, `names(): string[]`.

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/private-store.test.ts`:

```ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { PrivatePackageStore } from "../src/private-store.js";
import type { Audit } from "@sentinel/core";

const audit = { schema: 3, meta: {}, findings: [], capabilities: [], capabilityDelta: null,
  engine: { version: "x", rules: [], mode: "full" }, auditedAt: "t", durationMs: 0 } as unknown as Audit;
const put = (s: PrivatePackageStore, name: string, version: string, body = "x") =>
  s.put({ name, version, integrity: `sha512-${version}`, manifest: { name, version, dist: {} }, tarball: Buffer.from(body), audit, actor: "ci" });

describe("PrivatePackageStore", () => {
  test("put/get/has + versions + packument synthesis", () => {
    const s = new PrivatePackageStore();
    assert.equal(s.has("@acme/x"), false);
    put(s, "@acme/x", "1.0.0", "v1");
    put(s, "@acme/x", "1.1.0", "v2");
    assert.equal(s.has("@acme/x"), true);
    assert.deepEqual(s.versions("@acme/x").sort(), ["1.0.0", "1.1.0"]);
    assert.equal(s.getTarball("@acme/x", "1.1.0")?.toString(), "v2");
    assert.ok(s.getAudit("@acme/x", "1.0.0"));
    const pm = s.packument("@acme/x")!;
    assert.equal(pm.name, "@acme/x");
    assert.equal(pm["dist-tags"].latest, "1.1.0");           // highest semver
    assert.deepEqual(Object.keys(pm.versions).sort(), ["1.0.0", "1.1.0"]);
    assert.equal(s.packument("@acme/missing"), undefined);
  });

  test("persists to disk and reloads", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-priv-"));
    const a = new PrivatePackageStore(dir);
    put(a, "@acme/y", "2.0.0", "bytes-y");
    const b = new PrivatePackageStore(dir);  // fresh instance, same dir
    assert.equal(b.has("@acme/y"), true);
    assert.equal(b.getTarball("@acme/y", "2.0.0")?.toString(), "bytes-y");
    assert.equal(b.getVersion("@acme/y", "2.0.0")?.integrity, "sha512-2.0.0");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/private-store.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `PrivatePackageStore`**

Create `packages/proxy/src/private-store.ts`:

```ts
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import type { Audit } from "@sentinel/core";
import { cmpSemver } from "./upstream.js";

export interface StoredVersion {
  name: string;
  version: string;
  integrity: string;
  manifest: Record<string, unknown>;
  audit: Audit;
  actor: string;
  publishedAt: string;
}

export interface PrivatePackument {
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, Record<string, unknown>>;
}

interface Entry { meta: StoredVersion; tarball: Buffer; }

/** Authoritative store for published private packages: tarball bytes + manifest + the
 * policy-independent Audit. Optional filesystem persistence (`<dir>/<enc>/<version>/`). */
export class PrivatePackageStore {
  private byName = new Map<string, Map<string, Entry>>();

  constructor(private readonly dir?: string) {
    if (dir && existsSync(dir)) this.load(dir);
  }

  has(name: string): boolean {
    return (this.byName.get(name)?.size ?? 0) > 0;
  }

  names(): string[] {
    return [...this.byName.keys()];
  }

  versions(name: string): string[] {
    return [...(this.byName.get(name)?.keys() ?? [])];
  }

  getVersion(name: string, version: string): StoredVersion | undefined {
    return this.byName.get(name)?.get(version)?.meta;
  }

  getTarball(name: string, version: string): Buffer | undefined {
    return this.byName.get(name)?.get(version)?.tarball;
  }

  getAudit(name: string, version: string): Audit | undefined {
    return this.byName.get(name)?.get(version)?.meta.audit;
  }

  put(v: {
    name: string; version: string; integrity: string;
    manifest: Record<string, unknown>; tarball: Buffer; audit: Audit; actor: string;
  }): StoredVersion {
    const meta: StoredVersion = {
      name: v.name, version: v.version, integrity: v.integrity,
      manifest: v.manifest, audit: v.audit, actor: v.actor,
      publishedAt: new Date().toISOString(),
    };
    let versions = this.byName.get(v.name);
    if (!versions) { versions = new Map(); this.byName.set(v.name, versions); }
    versions.set(v.version, { meta, tarball: v.tarball });
    this.persist(meta, v.tarball);
    return meta;
  }

  packument(name: string): PrivatePackument | undefined {
    const versions = this.byName.get(name);
    if (!versions || versions.size === 0) return undefined;
    const versionDocs: Record<string, Record<string, unknown>> = {};
    let latest = "0.0.0";
    for (const [v, entry] of versions) {
      versionDocs[v] = entry.meta.manifest;
      if (cmpSemver(v, latest) > 0) latest = v;
    }
    return { name, "dist-tags": { latest }, versions: versionDocs };
  }

  // ---- persistence (best-effort, mirrors AuditStore's style) ----

  private dirFor(name: string, version: string): string {
    return join(this.dir!, encodeURIComponent(name), version);
  }

  private persist(meta: StoredVersion, tarball: Buffer): void {
    if (!this.dir) return;
    try {
      const d = this.dirFor(meta.name, meta.version);
      mkdirSync(d, { recursive: true });
      writeFileSync(join(d, "package.tgz"), tarball);
      const { ...metaJson } = meta;
      writeFileSync(join(d, "meta.json"), JSON.stringify(metaJson, null, 2));
    } catch {
      /* best-effort */
    }
  }

  private load(dir: string): void {
    for (const enc of readdirSync(dir)) {
      const name = decodeURIComponent(enc);
      const pkgDir = join(dir, enc);
      let versionDirs: string[];
      try { versionDirs = readdirSync(pkgDir); } catch { continue; }
      for (const version of versionDirs) {
        try {
          const meta = JSON.parse(readFileSync(join(pkgDir, version, "meta.json"), "utf8")) as StoredVersion;
          const tarball = readFileSync(join(pkgDir, version, "package.tgz"));
          let versions = this.byName.get(name);
          if (!versions) { versions = new Map(); this.byName.set(name, versions); }
          versions.set(version, { meta, tarball });
        } catch {
          /* skip a corrupt entry */
        }
      }
    }
  }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/private-store.test.ts`
Expected: PASS (both cases, incl. disk reload).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/private-store.ts packages/proxy/test/private-store.test.ts
git commit -m "feat(proxy): PrivatePackageStore (bytes + manifest + audit, packument synthesis, disk persistence)"
```

---

## Task 3: Proxy — private helpers (`isClaimed`, `parsePublishBody`, `publishTokenValid`)

**Files:**
- Create: `packages/proxy/src/private.ts`
- Test: `packages/proxy/test/private.test.ts`

**Interfaces:**
- Consumes: `matchPackage`, `type EnterprisePolicy` from `@sentinel/core`.
- Produces:
  - `isClaimed(name: string, policy: EnterprisePolicy): boolean`
  - `interface ParsedPublish { version: string; manifest: Record<string, unknown>; tarball: Buffer; declaredIntegrity: string | undefined }`
  - `parsePublishBody(name: string, body: unknown): ParsedPublish` (throws `Error` on a malformed payload)
  - `publishTokenValid(authHeader: string | undefined, tokens: string[]): boolean`

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/private.test.ts`:

```ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { describe, test } from "node:test";
import { isClaimed, parsePublishBody, publishTokenValid } from "../src/private.js";
import { DEFAULT_POLICY, type EnterprisePolicy } from "@sentinel/core";

const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

// Build a publish payload matching the captured npm shape.
function publishBody(name: string, version: string, bytes = "tarball-bytes", integrity?: string) {
  const data = Buffer.from(bytes).toString("base64");
  return {
    _id: name, name, "dist-tags": { latest: version },
    versions: { [version]: { name, version, dist: { integrity, shasum: "x", tarball: "http://x" } } },
    _attachments: { [`${name}-${version}.tgz`]: { content_type: "application/octet-stream", data, length: bytes.length } },
  };
}

describe("isClaimed", () => {
  test("matches exact + scope glob, anchored", () => {
    assert.equal(isClaimed("@acme/payments", policy(["@acme/*"])), true);
    assert.equal(isClaimed("acme-config", policy(["acme-config"])), true);
    assert.equal(isClaimed("@other/x", policy(["@acme/*"])), false);
    assert.equal(isClaimed("anything", policy([])), false);
  });
});

describe("parsePublishBody", () => {
  test("extracts the single new version, manifest, and base64 tarball", () => {
    const p = parsePublishBody("@acme/x", publishBody("@acme/x", "1.2.3", "hello", "sha512-zzz"));
    assert.equal(p.version, "1.2.3");
    assert.equal(p.tarball.toString(), "hello");
    assert.equal(p.declaredIntegrity, "sha512-zzz");
    assert.equal((p.manifest as { version: string }).version, "1.2.3");
  });
  test("throws on a body with no _attachments", () => {
    assert.throws(() => parsePublishBody("@acme/x", { versions: {} }));
  });
});

describe("publishTokenValid", () => {
  test("accepts a configured bearer token, rejects others/absent/none", () => {
    assert.equal(publishTokenValid("Bearer tok-1", ["tok-1", "tok-2"]), true);
    assert.equal(publishTokenValid("Bearer nope", ["tok-1"]), false);
    assert.equal(publishTokenValid(undefined, ["tok-1"]), false);
    assert.equal(publishTokenValid("Bearer tok-1", []), false); // no tokens configured ⇒ publishing disabled
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/private.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `private.ts`**

Create `packages/proxy/src/private.ts`:

```ts
import { Buffer } from "node:buffer";
import { matchPackage, type EnterprisePolicy } from "@sentinel/core";

export function isClaimed(name: string, policy: EnterprisePolicy): boolean {
  return (policy.privateNamespaces ?? []).some((p) => matchPackage(p, name));
}

export interface ParsedPublish {
  version: string;
  manifest: Record<string, unknown>;
  tarball: Buffer;
  declaredIntegrity: string | undefined;
}

/**
 * Parse an npm publish payload (PUT /:pkg). Each publish carries exactly one new
 * version, identified by the single `_attachments` key `<name>-<version>.tgz`.
 */
export function parsePublishBody(name: string, body: unknown): ParsedPublish {
  const b = body as {
    versions?: Record<string, Record<string, unknown>>;
    _attachments?: Record<string, { data?: string }>;
  };
  const attachments = b?._attachments ?? {};
  const keys = Object.keys(attachments);
  if (keys.length === 0) throw new Error("publish payload has no _attachments");
  const key = keys[0]!;
  const prefix = `${name}-`;
  if (!key.startsWith(prefix) || !key.endsWith(".tgz")) {
    throw new Error(`unexpected attachment name ${key} for ${name}`);
  }
  const version = key.slice(prefix.length, key.length - ".tgz".length);
  const data = attachments[key]?.data;
  if (typeof data !== "string") throw new Error("publish attachment has no base64 data");
  const manifest = (b.versions ?? {})[version];
  if (!manifest) throw new Error(`publish payload missing manifest for version ${version}`);
  const dist = manifest.dist as { integrity?: string } | undefined;
  return {
    version,
    manifest,
    tarball: Buffer.from(data, "base64"),
    declaredIntegrity: dist?.integrity,
  };
}

export function publishTokenValid(authHeader: string | undefined, tokens: string[]): boolean {
  if (tokens.length === 0) return false; // no tokens configured ⇒ publishing disabled (fail closed)
  const m = /^Bearer\s+(.+)$/i.exec(authHeader ?? "");
  return Boolean(m) && tokens.includes((m![1] ?? "").trim());
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/private.test.ts`
Expected: PASS (all cases).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/private.ts packages/proxy/test/private.test.ts
git commit -m "feat(proxy): private helpers — isClaimed, parsePublishBody, publishTokenValid"
```

---

## Task 4: Proxy — the publish route (`PUT /:pkg`)

**Files:**
- Modify: `packages/proxy/src/server.ts`, `packages/proxy/test/proxy.test.ts`
- Test: `packages/proxy/test/publish.test.ts`

**Interfaces:**
- Consumes: `PrivatePackageStore` (Task 2), `isClaimed`/`parsePublishBody`/`publishTokenValid` (Task 3), `runAudit`/`score`/`integrityOf` (core).
- Produces: `ServerOptions` gains `privateStore: PrivatePackageStore` (required) and `publishTokens?: string[]` (default `[]`). New `PUT` publish route. Global `express.json` no longer runs on `PUT`.

- [ ] **Step 1: Write the failing tests**

In `packages/proxy/test/proxy.test.ts`, add `privateStore` to the imports and to **every** `createServer({...})` call (each `before`/`startWith`):
```ts
import { PrivatePackageStore } from "../src/private-store.js";
// in each createServer options object, add:  privateStore: new PrivatePackageStore(),
```

Create `packages/proxy/test/publish.test.ts`:

```ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { DEFAULT_POLICY, integrityOf, type EnterprisePolicy } from "@sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
function ensure() { if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs")))
  execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" }); }

const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

// A benign tarball lifted from the fixtures, wrapped as an npm publish payload.
import { readFileSync } from "node:fs";
function publishPayload(name: string, version: string, tgz: Buffer) {
  const data = tgz.toString("base64");
  return JSON.stringify({
    _id: name, name, "dist-tags": { latest: version },
    versions: { [version]: { name, version, dist: { integrity: integrityOf(tgz), shasum: "x", tarball: "http://x" } } },
    _attachments: { [`${name}-${version}.tgz`]: { content_type: "application/octet-stream", data, length: tgz.length } },
  });
}

describe("publish route (PUT /:pkg)", () => {
  let server: Server; let base: string; let priv: PrivatePackageStore;
  const benign = () => readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
  const malicious = () => readFileSync(join(FIXTURES, ".tarballs", "color-stream-1.4.1.tgz"));

  before(async () => {
    ensure();
    priv = new PrivatePackageStore();
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(), privateStore: priv,
      enterprisePolicy: policy(["@acme/*"]), publishTokens: ["tok-1"], policy: "block",
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  const put = (name: string, body: string, headers: Record<string,string> = {}) =>
    fetch(`${base}/${encodeURIComponent(name)}`, { method: "PUT", headers: { "content-type": "application/json", ...headers }, body });

  test("401 without a valid token", async () => {
    const res = await put("@acme/widget", publishPayload("@acme/widget", "1.0.0", benign()));
    assert.equal(res.status, 401);
  });

  test("403 publishing a name outside any claimed namespace", async () => {
    const res = await put("not-claimed", publishPayload("not-claimed", "1.0.0", benign()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 403);
  });

  test("201 publishes a claimed package and stores it", async () => {
    const res = await put("@acme/widget", publishPayload("@acme/widget", "1.0.0", benign()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 201);
    assert.equal((await res.json()).ok, true);
    assert.equal(priv.has("@acme/widget"), true);
    assert.equal(priv.getTarball("@acme/widget", "1.0.0")?.length, benign().length);
  });

  test("409 on a duplicate version", async () => {
    const res = await put("@acme/widget", publishPayload("@acme/widget", "1.0.0", benign()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 409);
  });

  test("403 publish is rejected when the audit verdict is block", async () => {
    const res = await put("@acme/evil", publishPayload("@acme/evil", "1.0.0", malicious()), { authorization: "Bearer tok-1" });
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /block/i);
    assert.equal(priv.has("@acme/evil"), false); // not stored
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/publish.test.ts`
Expected: FAIL — `createServer` rejects `privateStore`/`publishTokens`; no PUT route.

- [ ] **Step 3: Implement the server changes**

In `packages/proxy/src/server.ts`:

Add to the `@sentinel/core` import: `runAudit, score, integrityOf` are already imported; no change there. Add new imports:
```ts
import { PrivatePackageStore } from "./private-store.js";
import { isClaimed, parsePublishBody, publishTokenValid } from "./private.js";
```

Extend `ServerOptions`:
```ts
  /** Authoritative store for published private packages (ADR-0010). */
  privateStore: PrivatePackageStore;
  /** Valid bearer tokens for publishing; empty ⇒ publishing disabled. */
  publishTokens?: string[];
```

In `createServer`, after the existing destructure add:
```ts
  const privateStore = opts.privateStore;
  const publishTokens = opts.publishTokens ?? [];
```

Replace the global JSON middleware line (`app.use(express.json({ limit: "1mb" }));`) with a parser that skips `PUT` (publishes parse their own larger body after auth):
```ts
  const jsonSmall = express.json({ limit: "1mb" });
  app.use((req, res, next) => (req.method === "PUT" ? next() : jsonSmall(req, res, next)));
  const jsonPublish = express.json({ limit: "64mb" });
```

Add the publish route just before the `// ---- dashboard ----` section:
```ts
  // ---- publish (PUT /:pkg) — authoritative private registry write path ----
  app.put(/^\/(.+)$/, requirePublishAuth, jsonPublish, async (req, res) => {
    const name = decodeURIComponent(req.params[0] ?? "");
    if (!isClaimed(name, enterprisePolicy)) {
      return res.status(403).json({ error: "not a private namespace", package: name });
    }
    try {
      const parsed = parsePublishBody(name, req.body);
      const integrity = integrityOf(parsed.tarball);
      if (parsed.declaredIntegrity && parsed.declaredIntegrity !== integrity) {
        return res.status(400).json({ error: "integrity mismatch", package: `${name}@${parsed.version}` });
      }
      if (privateStore.getVersion(name, parsed.version)) {
        return res.status(409).json({ error: "version already published", package: `${name}@${parsed.version}` });
      }
      const meta = {
        name, version: parsed.version,
        author: null, maintainers: [], license: null,
        hasInstallScripts: false, signatureStatus: "unknown" as const, integrity,
      };
      const audit = await runAudit({ meta, tarball: parsed.tarball });
      const report = score(audit, enterprisePolicy, policyHash);
      if (report.verdict === "block") {
        return res.status(403).json({
          error: "publish blocked by Sentinel policy", package: `${name}@${parsed.version}`,
          verdict: report.verdict,
          findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
        });
      }
      privateStore.put({ name, version: parsed.version, integrity, manifest: parsed.manifest, tarball: parsed.tarball, audit, actor: "publish-token" });
      console.log(`[private] published ${name}@${parsed.version} (verdict ${report.verdict})`);
      return res.status(201).json({ ok: true, id: name, rev: `1-${integrity.slice(7, 19)}` });
    } catch (err) {
      return sendError(res, err);
    }
  });
```

Add the auth middleware near the bottom helpers:
```ts
  function requirePublishAuth(req: Request, res: Response, next: () => void): void {
    if (!publishTokenValid(req.headers.authorization, publishTokens)) {
      res.status(401).json({ error: "authentication required to publish" });
      return;
    }
    next();
  }
```
(`requirePublishAuth` closes over `publishTokens`, so define it INSIDE `createServer` — place it just above the `app.put(...)` registration.)

- [ ] **Step 4: Run to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/publish.test.ts`
Expected: PASS (401, 403-not-claimed, 201, 409, 403-block). Also re-run the existing proxy suite to confirm the `createServer` option additions didn't break it:
Run: `node --import tsx --test packages/proxy/test/proxy.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/publish.test.ts packages/proxy/test/proxy.test.ts
git commit -m "feat(proxy): PUT publish route — token auth (pre-parse), audit-gate, store"
```

---

## Task 5: Proxy — claim-routing on the read paths (packument + tarball)

**Files:**
- Modify: `packages/proxy/src/server.ts`
- Test: `packages/proxy/test/private-serve.test.ts`

**Interfaces:**
- Consumes: `PrivatePackageStore`, `isClaimed`, `score`, `reconcile`.
- Produces: the packument GET and tarball GET branches route claimed names to the private store (fail-closed `404`, never public); private tarballs serve through the same gate with `x-sentinel-private: true`. A `gateAndSend` helper shared by public + private tarball serving.

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/private-serve.test.ts`:

```ts
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { DEFAULT_POLICY, runAudit, integrityOf, type EnterprisePolicy } from "@sentinel/core";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "..", "..", "..", "fixtures");
function ensure() { if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs")))
  execFileSync("npx", ["tsx", join(HERE, "..", "..", "..", "scripts", "make-fixtures.ts")], { stdio: "ignore" }); }
const policy = (ns: string[]): EnterprisePolicy => ({ ...DEFAULT_POLICY, privateNamespaces: ns });

describe("private serve routing", () => {
  let server: Server; let base: string; let priv: PrivatePackageStore;

  before(async () => {
    ensure();
    priv = new PrivatePackageStore();
    // Seed a published private package directly (a benign tarball).
    const tgz = readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.1.tgz"));
    const meta = { name: "@acme/widget", version: "1.0.0", author: null, maintainers: [], license: null,
      hasInstallScripts: false, signatureStatus: "unknown" as const, integrity: integrityOf(tgz) };
    const audit = await runAudit({ meta, tarball: tgz });
    priv.put({ name: "@acme/widget", version: "1.0.0", integrity: integrityOf(tgz),
      manifest: { name: "@acme/widget", version: "1.0.0", dist: {} }, tarball: tgz, audit, actor: "seed" });

    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES),
      store: new AuditStore(), approvals: new ApprovalStore(), privateStore: priv,
      enterprisePolicy: policy(["@acme/*"]), policy: "block",
    });
    await new Promise<void>((r) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; r(); }); });
  });
  after(() => server?.close());

  test("claimed packument is synthesized with rewritten tarball URLs", async () => {
    const doc = await (await fetch(`${base}/@acme%2fwidget`)).json();
    assert.equal(doc.name, "@acme/widget");
    assert.ok(doc.versions["1.0.0"]);
    assert.ok(String(doc.versions["1.0.0"].dist.tarball).startsWith(base));
  });

  test("claimed tarball is served privately with x-sentinel-private", async () => {
    const res = await fetch(`${base}/@acme/widget/-/widget-1.0.0.tgz`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("x-sentinel-private"), "true");
    assert.ok((await res.arrayBuffer()).byteLength > 0);
  });

  test("claimed but UNPUBLISHED name → 404, never public", async () => {
    const pm = await fetch(`${base}/@acme%2fmissing`);
    assert.equal(pm.status, 404);
    const tb = await fetch(`${base}/@acme/missing/-/missing-9.9.9.tgz`);
    assert.equal(tb.status, 404);
  });

  test("non-claimed name still passes through to public (fixtures)", async () => {
    const doc = await (await fetch(`${base}/leftpad-lite`)).json();
    assert.ok(doc.versions["1.0.1"], "public passthrough unchanged");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/private-serve.test.ts`
Expected: FAIL — claimed names currently fall through to the public upstream (404 from fixtures / wrong body), no `x-sentinel-private`.

- [ ] **Step 3: Refactor the tarball gate into `gateAndSend`, then route claimed reads**

In `packages/proxy/src/server.ts`, extract the gate logic into a helper inside `createServer` (place it next to `reconcile`):
```ts
  function gateAndSend(res: Response, pkg: string, version: string, report: AuditReport, tarball: Buffer, isPrivate: boolean): Response | void {
    const rec = reconcile(report);
    res.setHeader("x-sentinel-score", String(report.score));
    res.setHeader("x-sentinel-verdict", report.verdict);
    res.setHeader("x-sentinel-findings", String(report.findings.length));
    res.setHeader("x-sentinel-capabilities", String(report.capabilities.length));
    res.setHeader("x-sentinel-approval", rec.state);
    res.setHeader("x-sentinel-policy", report.policy.version);
    if (isPrivate) res.setHeader("x-sentinel-private", "true");
    if (policy === "block") {
      if (report.verdict === "block") {
        return res.status(403).json({ error: "blocked by Sentinel policy", package: `${pkg}@${version}`,
          score: report.score, verdict: report.verdict,
          findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })) });
      }
      if (rec.state === "denied") return res.status(403).json({ error: "approval denied by Sentinel policy", package: `${pkg}@${version}` });
      if (rec.state === "required") return res.status(403).json({ error: "approval required by Sentinel policy",
        package: `${pkg}@${version}`, approvalRequired: rec.approvalRequired,
        findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })) });
    }
    res.setHeader("content-type", "application/octet-stream");
    return res.send(tarball);
  }
```

In the catch-all GET route's **tarball branch**, replace the body (the part from `const { report, tarball } = await auditVersion(...)` through `return res.send(tarball);`) with claim routing:
```ts
      try {
        if (isClaimed(pkg, enterprisePolicy)) {
          const audit = privateStore.getAudit(pkg, version);
          const tarball = privateStore.getTarball(pkg, version);
          if (!audit || !tarball) return res.status(404).json({ error: "private package not found", package: `${pkg}@${version}` });
          const report = score(audit, enterprisePolicy, policyHash);
          return gateAndSend(res, pkg, version, report, tarball, true);
        }
        const { report, tarball } = await auditVersion(pkg, version);
        return gateAndSend(res, pkg, version, report, tarball, false);
      } catch (err) {
        return sendError(res, err);
      }
```

In the **packument branch** (the `else` after the tarball branch), route claimed names first:
```ts
    // Packument
    try {
      const base = `${req.protocol}://${req.get("host")}`;
      if (isClaimed(path, enterprisePolicy)) {
        const pm = privateStore.packument(path);
        if (!pm) return res.status(404).json({ error: "private package not found", package: path });
        for (const [v, manifest] of Object.entries(pm.versions)) {
          (manifest as { dist?: { tarball?: string } }).dist = { ...(manifest as { dist?: object }).dist, tarball: `${base}/${path}/-/${shortName(path)}-${v}.tgz` };
        }
        res.setHeader("content-type", "application/json");
        res.setHeader("x-sentinel-private", "true");
        return res.json(pm);
      }
      const pm = await upstream.getPackument(path);
      for (const [v, manifest] of Object.entries(pm.doc.versions ?? {})) {
        const fileName = `${shortName(path)}-${v}.tgz`;
        (manifest as { dist: { tarball: string } }).dist.tarball = `${base}/${path}/-/${fileName}`;
      }
      res.setHeader("content-type", "application/json");
      return res.json(pm.doc);
    } catch (err) {
      return sendError(res, err);
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/private-serve.test.ts packages/proxy/test/proxy.test.ts`
Expected: PASS — private routing works AND the existing public proxy tests still pass (the `gateAndSend` refactor preserves public behavior).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/private-serve.test.ts
git commit -m "feat(proxy): claim-route reads to the private store (fail-closed 404); shared gateAndSend"
```

---

## Task 6: Proxy — wiring, `/-/private` status, telemetry

**Files:**
- Modify: `packages/proxy/src/index.ts`, `packages/proxy/src/server.ts`, `scripts/demo.ts`
- Test: `packages/proxy/test/private-serve.test.ts` (extend)

**Interfaces:**
- Consumes: `PrivatePackageStore`, env `SENTINEL_PRIVATE_STORE`, `SENTINEL_PUBLISH_TOKENS`, `SENTINEL_SHADOW_PROBE`.
- Produces: `GET /-/private` status endpoint; env-driven wiring; `scripts/demo.ts` + all `createServer` callers pass `privateStore`.

- [ ] **Step 1: Write the failing test**

Append to `packages/proxy/test/private-serve.test.ts` (inside the same describe):
```ts
  test("GET /-/private lists claims and published packages", async () => {
    const data = await (await fetch(`${base}/-/private`)).json();
    assert.deepEqual(data.claims, ["@acme/*"]);
    assert.ok(data.packages.some((p: { name: string }) => p.name === "@acme/widget"));
  });
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --import tsx --test packages/proxy/test/private-serve.test.ts`
Expected: FAIL — `/-/private` returns the catch-all 404 / wrong shape.

- [ ] **Step 3: Add the `/-/private` route**

In `packages/proxy/src/server.ts`, add near the other `/-/` routes (e.g. after `/-/approvals`):
```ts
  app.get("/-/private", (_req, res) => {
    res.json({
      claims: enterprisePolicy.privateNamespaces ?? [],
      packages: privateStore.names().map((name) => ({ name, versions: privateStore.versions(name) })),
    });
  });
```

- [ ] **Step 4: Wire env in `index.ts` + fix demo.ts + remaining callers**

In `packages/proxy/src/index.ts`, add the import:
```ts
import { PrivatePackageStore } from "./private-store.js";
```
add an export line with the others:
```ts
export { PrivatePackageStore } from "./private-store.js";
```
and in `main()`, build + pass it (after the `approvals` line):
```ts
  const privateStore = new PrivatePackageStore(process.env.SENTINEL_PRIVATE_STORE);
  const publishTokens = (process.env.SENTINEL_PUBLISH_TOKENS ?? "").split(",").map((t) => t.trim()).filter(Boolean);
```
change the `createServer({...})` call to include them:
```ts
  const app = createServer({ upstream, store, approvals, privateStore, publishTokens, enterprisePolicy, policyHash, policy, publicDir });
```
and add a startup log line inside the `app.listen` callback (before the `SENTINEL_BOOT_EXIT` line):
```ts
    const claims = enterprisePolicy.privateNamespaces ?? [];
    console.log(`  private  : ${claims.length ? claims.join(", ") : "none"}  (publish ${publishTokens.length ? "enabled" : "disabled"})`);
```

In `scripts/demo.ts`, add `privateStore: new PrivatePackageStore()` to its `createServer({...})` options, and the import:
```ts
import { PrivatePackageStore } from "../packages/proxy/src/private-store.js";
```

- [ ] **Step 5: Run to verify it passes**

Run: `npx tsc --build --force packages/proxy && node --import tsx --test packages/proxy/test/private-serve.test.ts`
Expected: PASS. Then confirm the demo still runs:
Run: `npm run demo 2>&1 | grep -iE "HTTP 403|verdict: block|private"`
Expected: malicious tarball blocked; a `private  : none` startup line.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/index.ts packages/proxy/src/server.ts scripts/demo.ts packages/proxy/test/private-serve.test.ts
git commit -m "feat(proxy): /-/private status, env wiring (SENTINEL_PRIVATE_STORE/PUBLISH_TOKENS), demo fix"
```

---

## Task 7: Documentation

**Files:**
- Create: `docs/adr/0015-private-registry-publish-protocol.md`
- Modify: `docs/adr/0010-private-namespace-override.md`, `ARCHITECTURE.md`, `CLAUDE.md`

- [ ] **Step 1: ADR-0010 → Accepted**

In `docs/adr/0010-private-namespace-override.md`, change `**Status:** Proposed` to `**Status:** Accepted`.

- [ ] **Step 2: Write ADR-0015**

Create `docs/adr/0015-private-registry-publish-protocol.md`:

```md
# ADR-0015: Private-registry publish protocol, auth, and fail-closed routing

**Status:** Accepted
**Date:** 2026-06-25
**Phase:** 2 (implements ADR-0010 Option A)

## Context
ADR-0010 makes the proxy authoritative for claimed names. Realizing it as full
hosting requires an npm-compatible publish path and an authoritative serve path.

## Decision
1. **Claims live in the signed `EnterprisePolicy`** (`privateNamespaces` globs,
   reusing `matchPackage`). A claim is security-critical, so signing/versioning
   protects it; a tampered or malformed policy fails closed at boot (ADR-0014).
2. **Fail-closed routing:** for a claimed name the proxy serves only from the
   `PrivatePackageStore` and NEVER consults the public upstream — a claimed but
   unpublished name returns `404`. Non-claimed names pass through unchanged
   (the scoped exception to ADR-0005).
3. **Publish protocol (captured empirically from npm 11.x):** `PUT /:pkg` (scoped
   `%2f`-encoded), `Authorization: Bearer <token>`, JSON body with one new version
   in `versions` + its base64 tarball in `_attachments`. npm pre-GETs the packument
   (a `404` means "new package, proceed to PUT") and sends only the new version per
   publish — no client-side merge, no `_rev`. The store accumulates versions.
4. **Auth before parse:** publish requires a configured bearer token
   (`SENTINEL_PUBLISH_TOKENS`); the check runs in middleware BEFORE the body parser,
   and the global 1MB JSON parser is bypassed for `PUT` (a real tarball exceeds 1MB).
5. **Audited + policy-gated publish:** every publish is `runAudit` + `score(policy)`;
   a `block` verdict is rejected and not stored.
6. **Same install-time gate** for private packages (score + 0011 approval gate);
   publish and approval are orthogonal — publishing does not auto-approve.
7. **Telemetry** is local-only by default; the public-shadow probe is opt-in
   (`SENTINEL_SHADOW_PROBE`) because probing leaks claimed names to public npm.

## Consequences
- Sentinel takes on registry-authoritative duties (storage, availability) for claimed
  names. Deferred: unpublish/deprecate, dist-tags beyond `latest`, GC/durability,
  concurrent-publish locking, access levels, multi-user roles, federation.
- The transparency invariant (ADR-0005) now has a documented, claim-scoped exception.
```

- [ ] **Step 3: Update ARCHITECTURE.md**

In `ARCHITECTURE.md`, add a subsection after the policy-loading section (§3.4):
```md
### 3.5 Private namespace (Phase 2.3, ADR-0010/0015)

Names matching the signed policy's `privateNamespaces` globs are served
authoritatively from a `PrivatePackageStore` and NEVER from public npm (fail-closed:
unpublished claimed name ⇒ 404). `npm publish` (`PUT /:pkg`, bearer-token auth before
body parse, 64MB limit) is audited + policy-gated (a `block` verdict is rejected).
Private installs use the same score + approval gate as public, with `x-sentinel-private`.
Non-claimed names pass through transparently (the scoped exception to ADR-0005).
`GET /-/private` reports claims + published packages.
```
And note in §5 (data model) that `EnterprisePolicy` gains `privateNamespaces: string[]`.

- [ ] **Step 4: Update CLAUDE.md**

Run `npm test 2>&1 | tail -4`, note the count `N`, and update the two `71/71` references to `N/N`. Add a one-line note under the invariants list:
```md
7. **Claimed names are authoritative, not passthrough.** Names matching the signed
   policy's `privateNamespaces` are served only from the private store and never from
   public npm (fail-closed). Everything else still passes through (ADR-0010/0015).
```

- [ ] **Step 5: Commit**

```bash
git add docs/adr ARCHITECTURE.md CLAUDE.md
git commit -m "docs: accept ADR-0010, add ADR-0015, document private namespace in ARCHITECTURE + CLAUDE"
```

---

## Task 8: Full-suite verification

**Files:** none.

- [ ] **Step 1: Build + full suite**

Run: `npm run build && npm test 2>&1 | grep -E '^ℹ (tests|pass|fail)' | tail -3`
Expected: clean build; all pass. Update CLAUDE.md (Task 7 Step 4) if the count differs.

- [ ] **Step 2: Fail-closed invariant (explicit)**

Run: `node --import tsx --test --test-name-pattern "claimed but UNPUBLISHED" packages/proxy/test/private-serve.test.ts`
Expected: PASS — a claimed, unpublished name 404s for both packument and tarball (public never consulted).

- [ ] **Step 3: Real `npm publish` end-to-end (manual, single command)**

Run (one command — background processes don't persist across invocations here):
```bash
cd /Users/tonibergholm/Developer/claude/pkg-registry && \
SENTINEL_UPSTREAM=fixtures SENTINEL_POLICY=block SENTINEL_PUBLISH_TOKENS=tok \
SENTINEL_POLICY_FILE= node --import tsx -e '
import { createServer } from "./packages/proxy/src/server.js";
import { AuditStore } from "./packages/proxy/src/store.js";
import { ApprovalStore } from "./packages/proxy/src/approvals.js";
import { PrivatePackageStore } from "./packages/proxy/src/private-store.js";
import { LocalFixtureUpstream } from "./packages/proxy/src/upstream.js";
import { DEFAULT_POLICY } from "./packages/core/dist/index.js";
import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os"; import { join } from "node:path";
const app = createServer({ upstream: new LocalFixtureUpstream("fixtures"), store: new AuditStore(),
  approvals: new ApprovalStore(), privateStore: new PrivatePackageStore(),
  enterprisePolicy: { ...DEFAULT_POLICY, privateNamespaces: ["@acme/*"] }, publishTokens: ["tok"], policy: "block" });
const s = app.listen(0, () => {
  const port = s.address().port;
  const dir = mkdtempSync(join(tmpdir(), "pub-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@acme/demo", version: "1.0.0" }));
  writeFileSync(join(dir, "index.js"), "module.exports=1;");
  writeFileSync(join(dir, ".npmrc"), `registry=http://localhost:${port}/\n//localhost:${port}/:_authToken=tok\n`);
  try { execSync("npm publish", { cwd: dir, stdio: "inherit" }); } catch (e) {}
  const r = execSync(`curl -s localhost:${port}/-/private`).toString();
  console.log("PRIVATE STATUS:", r);
  s.close();
});
'
# Phase 23 — Trust Boundary (ADR-0036) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the proxy trusting attacker-influenceable values at its network boundary: pin outbound tarball fetches to allowed origins (SSRF fix) and replace inbound Host-header-derived rewrite URLs with a configured public base URL.

**Architecture:** A new pure module `packages/proxy/src/net-config.ts` holds all parsing/validation (origin allowlist, public base URL, loopback detection, tarball-URL assertion) — no I/O, no env access. `NpmUpstream.getTarball` enforces origin pinning before any fetch; `createServer` gains a `publicBaseUrl` option with a loopback-only Host fallback (421 otherwise); `index.ts` owns the fail-closed FATAL env parsing, same posture as `SENTINEL_AUTH_PUBKEY`.

**Tech Stack:** Node 24 / TypeScript, Express 5, `node:test` + `tsx`, WHATWG `URL` for all origin normalization (no hand-rolled parsing).

**Spec:** `docs/superpowers/specs/2026-07-09-security-hardening-phases-design.md` (Phase 23 section).

## Global Constraints

- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts` sources.
- Tests are hermetic: local `127.0.0.1` listeners only; **never** hit live npm. `LocalFixtureUpstream` never fetches over the network (its `dist.tarball` is `fixture:…`), so the origin check lives only in `NpmUpstream`.
- Fail-closed env posture: a set-but-invalid env var is `FATAL` + `process.exit(1)` at startup (mirror `resolveAdvisories` in `packages/proxy/src/index.ts:90`).
- No scoring changes anywhere — invariants #1–#4 untouched. Transparency (#5): we still rewrite only `dist.tarball`.
- Child-process boot tests use **async** `execFile` (promisified), never `execFileSync` (deadlocks the in-process proxy).
- Run a single test file with: `node --import tsx --test packages/proxy/test/<file>.test.ts` from the repo root. Full suite: `npm test`.
- Build: `npm run build` (tsc project references). If `rm` of `dist/` fails with EPERM, use `npx tsc --build --force packages/proxy` instead of deleting.
- Commit style: `feat(phase23): …` / `test(phase23): …` / `docs(phase23): …`.

---

### Task 1: Pure net-config helpers

**Files:**
- Create: `packages/proxy/src/net-config.ts`
- Test: `packages/proxy/test/net-config.test.ts`

**Interfaces:**
- Consumes: nothing (pure, stdlib `URL` only).
- Produces (used by Tasks 2–4):
  - `parseTarballOrigins(raw: string): string[]` — throws on any invalid entry
  - `parsePublicBaseUrl(raw: string): string` — throws; returns trailing-slash-stripped
  - `isLoopbackHost(hostHeader: string): boolean`
  - `assertAllowedTarballUrl(url: string, registryOrigin: string, extraOrigins: readonly string[]): void` — throws plain `Error` on a disallowed URL

- [ ] **Step 1: Write the failing tests**

```typescript
// packages/proxy/test/net-config.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  parseTarballOrigins,
  parsePublicBaseUrl,
  isLoopbackHost,
  assertAllowedTarballUrl,
} from "../src/net-config.js";

describe("parseTarballOrigins", () => {
  test("parses a comma-separated list into origins", () => {
    assert.deepEqual(
      parseTarballOrigins("https://cdn.example.com, http://mirror.corp:8080"),
      ["https://cdn.example.com", "http://mirror.corp:8080"],
    );
  });

  test("normalizes case and default ports via URL.origin", () => {
    assert.deepEqual(parseTarballOrigins("HTTPS://CDN.Example.com:443"), ["https://cdn.example.com"]);
  });

  test("rejects an entry with a path", () => {
    assert.throws(() => parseTarballOrigins("https://cdn.example.com/tarballs"), /bare origin/);
  });

  test("rejects an entry with a query", () => {
    assert.throws(() => parseTarballOrigins("https://cdn.example.com/?x=1"), /bare origin/);
  });

  test("rejects a non-http(s) protocol", () => {
    assert.throws(() => parseTarballOrigins("ftp://cdn.example.com"), /http/);
  });

  test("rejects garbage", () => {
    assert.throws(() => parseTarballOrigins("not a url"));
  });

  test("empty string yields an empty list", () => {
    assert.deepEqual(parseTarballOrigins(""), []);
  });
});

describe("parsePublicBaseUrl", () => {
  test("accepts an https URL and strips the trailing slash", () => {
    assert.equal(parsePublicBaseUrl("https://sentinel.corp.example/"), "https://sentinel.corp.example");
  });

  test("accepts a path prefix (proxy mounted behind an LB route)", () => {
    assert.equal(parsePublicBaseUrl("https://lb.corp.example/sentinel/"), "https://lb.corp.example/sentinel");
  });

  test("rejects a query string", () => {
    assert.throws(() => parsePublicBaseUrl("https://x.example/?a=1"), /query or fragment/);
  });

  test("rejects a non-http(s) protocol", () => {
    assert.throws(() => parsePublicBaseUrl("ftp://x.example"), /http/);
  });

  test("rejects garbage", () => {
    assert.throws(() => parsePublicBaseUrl("not a url"));
  });
});

describe("isLoopbackHost", () => {
  test("localhost with and without port", () => {
    assert.equal(isLoopbackHost("localhost"), true);
    assert.equal(isLoopbackHost("localhost:4873"), true);
  });

  test("127.0.0.0/8 with port", () => {
    assert.equal(isLoopbackHost("127.0.0.1:4873"), true);
    assert.equal(isLoopbackHost("127.1.2.3:80"), true);
  });

  test("IPv6 loopback", () => {
    assert.equal(isLoopbackHost("[::1]:4873"), true);
  });

  test("non-loopback hosts are false", () => {
    assert.equal(isLoopbackHost("registry.evil.example"), false);
    assert.equal(isLoopbackHost("192.168.1.10:4873"), false);
    assert.equal(isLoopbackHost("127.0.0.1.evil.example"), false);
    assert.equal(isLoopbackHost(""), false);
  });
});

describe("assertAllowedTarballUrl", () => {
  const registry = "https://registry.npmjs.org";

  test("same-origin tarball URL passes", () => {
    assertAllowedTarballUrl("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", registry, []);
  });

  test("allowlisted extra origin passes", () => {
    assertAllowedTarballUrl("https://cdn.corp.example/lodash.tgz", registry, ["https://cdn.corp.example"]);
  });

  test("cross-origin URL throws", () => {
    assert.throws(
      () => assertAllowedTarballUrl("http://169.254.169.254/latest/meta-data", registry, []),
      /not the registry origin/,
    );
  });

  test("same host but different port is a different origin", () => {
    assert.throws(() => assertAllowedTarballUrl("https://registry.npmjs.org:8443/x.tgz", registry, []), /not the registry origin/);
  });

  test("non-http(s) protocol throws even for a matching host", () => {
    assert.throws(() => assertAllowedTarballUrl("file:///etc/passwd", registry, []), /protocol/);
  });

  test("malformed URL throws", () => {
    assert.throws(() => assertAllowedTarballUrl("not a url", registry, []), /malformed/);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --import tsx --test packages/proxy/test/net-config.test.ts`
Expected: FAIL — `Cannot find module '../src/net-config.js'`

- [ ] **Step 3: Write the implementation**

```typescript
// packages/proxy/src/net-config.ts
/**
 * Pure network-trust configuration helpers (Phase 23, ADR-0036).
 * Parsing + validation only — no I/O, no env access. `index.ts` owns the
 * fail-closed FATAL wrapping; `upstream.ts`/`server.ts` own enforcement.
 * All origin comparison goes through WHATWG `URL.origin` (normalizes case
 * and default ports) — never hand-rolled string matching.
 */

function toHttpUrl(raw: string, what: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${what} is not a valid URL: "${raw}"`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`${what} must be http(s), got "${url.protocol}" ("${raw}")`);
  }
  return url;
}

/**
 * Parse the comma-separated `SENTINEL_TARBALL_ORIGINS` allowlist. Each entry
 * must be a bare http(s) origin — no path, query, or fragment. Throws on any
 * invalid entry (the caller FATALs). Empty/blank input ⇒ [].
 */
export function parseTarballOrigins(raw: string): string[] {
  const origins: string[] = [];
  for (const entry of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const url = toHttpUrl(entry, "SENTINEL_TARBALL_ORIGINS entry");
    if (url.pathname !== "/" || url.search || url.hash) {
      throw new Error(`SENTINEL_TARBALL_ORIGINS entry must be a bare origin (no path/query/hash): "${entry}"`);
    }
    origins.push(url.origin);
  }
  return origins;
}

/**
 * Validate `SENTINEL_PUBLIC_BASE_URL`: http(s), no query/fragment. A path
 * prefix IS allowed (proxy mounted behind a load-balancer route). Returns the
 * URL with any trailing slash stripped, ready for `${base}/pkg/-/file.tgz`.
 */
export function parsePublicBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  const url = toHttpUrl(trimmed, "SENTINEL_PUBLIC_BASE_URL");
  if (url.search || url.hash) {
    throw new Error(`SENTINEL_PUBLIC_BASE_URL must not have a query or fragment: "${raw}"`);
  }
  return trimmed.replace(/\/+$/, "");
}

/**
 * True iff a Host header names loopback — `localhost`, `127.0.0.0/8`, or
 * `[::1]` — with any port. The safe zero-config dev case: only here may the
 * packument rewrite derive its base URL from the request (ADR-0036).
 */
export function isLoopbackHost(hostHeader: string): boolean {
  if (!hostHeader) return false;
  let hostname: string;
  try {
    hostname = new URL(`http://${hostHeader}`).hostname;
  } catch {
    return false;
  }
  return hostname === "localhost" || hostname === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

/**
 * Throw unless `url` is http(s) AND its origin is the configured registry
 * origin or in the extra allowlist. Called BEFORE any fetch — a disallowed
 * URL is never requested at all, so there is no DNS/IP surface (ADR-0036).
 */
export function assertAllowedTarballUrl(url: string, registryOrigin: string, extraOrigins: readonly string[]): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`malformed tarball URL "${url}"`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`tarball URL protocol "${parsed.protocol}" is not allowed ("${url}")`);
  }
  if (parsed.origin !== registryOrigin && !extraOrigins.includes(parsed.origin)) {
    throw new Error(`tarball origin ${parsed.origin} is not the registry origin ${registryOrigin} and not in SENTINEL_TARBALL_ORIGINS`);
  }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --import tsx --test packages/proxy/test/net-config.test.ts`
Expected: PASS (all ~20 subtests)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/net-config.ts packages/proxy/test/net-config.test.ts
git commit -m "feat(phase23): pure net-config helpers — origin allowlist, public base URL, loopback detection (ADR-0036)"
```

---

### Task 2: Tarball origin pinning in NpmUpstream (SSRF fix)

**Files:**
- Modify: `packages/proxy/src/upstream.ts:77-104` (`NpmUpstream` constructor + `getTarball`)
- Test: `packages/proxy/test/tarball-origin-e2e.test.ts`

**Interfaces:**
- Consumes: `assertAllowedTarballUrl` from `./net-config.js` (Task 1).
- Produces: `NpmUpstream` constructor signature becomes
  `constructor(registry = "https://registry.npmjs.org", tarballOrigins: readonly string[] = [])`
  (Task 4 passes the parsed allowlist as the second argument). A disallowed
  tarball URL rejects with `HttpError(502, "refusing tarball fetch for <pkg>@<version>: …")`.

- [ ] **Step 1: Write the failing test**

A hermetic local "registry" on `127.0.0.1` serves packuments whose `dist.tarball` points wherever the test wants, plus a canary listener that records any hit — proving a disallowed URL is never fetched.

```typescript
// packages/proxy/test/tarball-origin-e2e.test.ts
import assert from "node:assert/strict";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, test } from "node:test";
import { NpmUpstream, HttpError } from "../src/upstream.js";

const TARBALL_BYTES = "fake-tarball-bytes";

function listen(server: Server): Promise<string> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

describe("NpmUpstream tarball origin pinning (hermetic local registry)", () => {
  let canaryHit = false;
  let canary: Server, registry: Server;
  let canaryBase = "", registryBase = "";

  before(async () => {
    // Canary: an "attacker" origin. Any request here trips canaryHit.
    canary = createHttpServer((_req, res) => {
      canaryHit = true;
      res.end(TARBALL_BYTES);
    });
    canaryBase = await listen(canary);

    // Registry: packuments name a tarball URL per package.
    registry = createHttpServer((req, res) => {
      const pkg = (req.url ?? "").split("/")[1] ?? "";
      if (pkg === "good-pkg" || pkg === "evil-pkg") {
        const tarball = pkg === "good-pkg"
          ? `${registryBase}/good-pkg/-/good-pkg-1.0.0.tgz`
          : `${canaryBase}/evil.tgz`;
        if ((req.url ?? "").includes("/-/")) {
          res.end(TARBALL_BYTES); // same-origin tarball path
          return;
        }
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({
          name: pkg,
          versions: { "1.0.0": { name: pkg, version: "1.0.0", dist: { tarball } } },
        }));
        return;
      }
      res.statusCode = 404;
      res.end("{}");
    });
    registryBase = await listen(registry);
  });

  after(() => { canary.close(); registry.close(); });
  beforeEach(() => { canaryHit = false; });

  test("same-origin tarball URL is fetched", async () => {
    const up = new NpmUpstream(registryBase);
    const buf = await up.getTarball("good-pkg", "1.0.0");
    assert.equal(buf.toString(), TARBALL_BYTES);
  });

  test("cross-origin tarball URL is refused with 502 — and never requested", async () => {
    const up = new NpmUpstream(registryBase);
    await assert.rejects(
      () => up.getTarball("evil-pkg", "1.0.0"),
      (err: unknown) => err instanceof HttpError && err.status === 502 && /not the registry origin/.test(err.message),
    );
    assert.equal(canaryHit, false, "the disallowed origin must never receive a request");
  });

  test("an origin in the allowlist is admitted", async () => {
    const up = new NpmUpstream(registryBase, [new URL(canaryBase).origin]);
    const buf = await up.getTarball("evil-pkg", "1.0.0");
    assert.equal(buf.toString(), TARBALL_BYTES);
    assert.equal(canaryHit, true);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/tarball-origin-e2e.test.ts`
Expected: FAIL — the cross-origin test fetches the canary (`canaryHit` is `true`, no rejection), and the allowlist test fails because `NpmUpstream` takes no second constructor argument yet. The same-origin test passes already.

- [ ] **Step 3: Implement origin pinning**

In `packages/proxy/src/upstream.ts`, add the import at the top (after the existing `@sentinel/core` import):

```typescript
import { assertAllowedTarballUrl } from "./net-config.js";
```

Replace the `NpmUpstream` constructor and `getTarball` (currently lines 77–104):

```typescript
/** Fetches from the real npm registry. */
export class NpmUpstream implements Upstream {
  readonly name = "npm";
  /** Origin tarball URLs must match — a packument-controlled URL is never fetched cross-origin (ADR-0036). */
  private readonly registryOrigin: string;
  constructor(
    private readonly registry = "https://registry.npmjs.org",
    private readonly tarballOrigins: readonly string[] = [],
  ) {
    this.registryOrigin = new URL(registry).origin;
  }
```

(`getPackument` and `getAttestations` are unchanged.) New `getTarball`:

```typescript
  async getTarball(pkg: string, version: string): Promise<Buffer> {
    const pm = await this.getPackument(pkg);
    const url = pm.doc.versions[version]?.dist?.tarball;
    if (!url) throw new HttpError(404, `no tarball for ${pkg}@${version}`);
    try {
      assertAllowedTarballUrl(url, this.registryOrigin, this.tarballOrigins);
    } catch (err) {
      throw new HttpError(502, `refusing tarball fetch for ${pkg}@${version}: ${(err as Error).message}`);
    }
    const res = await fetch(url);
    if (!res.ok) throw new HttpError(res.status, `upstream tarball ${pkg}@${version}: ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/tarball-origin-e2e.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Run the proxy package's existing tests (regression)**

Run: `node --import tsx --test packages/proxy/test/proxy.test.ts packages/proxy/test/audit-tree-e2e.test.ts`
Expected: PASS — `LocalFixtureUpstream` (used by all hermetic tests) is untouched; only `NpmUpstream` changed.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/upstream.ts packages/proxy/test/tarball-origin-e2e.test.ts
git commit -m "feat(phase23): pin tarball fetches to registry origin + SENTINEL_TARBALL_ORIGINS allowlist — SSRF fix (ADR-0036)"
```

---

### Task 3: publicBaseUrl in createServer (Host-header fix)

**Files:**
- Modify: `packages/proxy/src/server.ts` — `ServerOptions` (~line 46), `createServer` locals (~line 110), packument rewrite (~line 613)
- Test: `packages/proxy/test/public-base-url-e2e.test.ts`

**Interfaces:**
- Consumes: `isLoopbackHost` from `./net-config.js` (Task 1); `HttpError` (already imported in server.ts).
- Produces: `ServerOptions.publicBaseUrl?: string` — Task 4 passes the parsed env value. Behavior: set ⇒ rewrites use it and Host is ignored; unset + loopback Host ⇒ request-derived (unchanged dev behavior); unset + non-loopback Host ⇒ `421 { error: … }`.

- [ ] **Step 1: Write the failing test**

Uses raw `node:http` requests so the `Host` header can be spoofed (WHATWG `fetch` may normalize it). `leftpad-lite@1.0.0` is a benign package in the committed fixture registry.

```typescript
// packages/proxy/test/public-base-url-e2e.test.ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { request as httpRequest } from "node:http";
import { before, describe, test } from "node:test";
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

function boot(publicBaseUrl?: string): Promise<{ server: Server; port: number }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), publicBaseUrl,
  });
  return new Promise((r) => { const s = app.listen(0, () => r({ server: s, port: (s.address() as AddressInfo).port })); });
}

/** GET via raw node:http so we control the Host header exactly. */
function get(port: number, path: string, hostHeader?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path, headers: hostHeader ? { host: hostHeader } : undefined },
      (res) => {
        let data = "";
        res.on("data", (c: Buffer) => (data += c.toString()));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("packument rewrite base URL vs Host header (ADR-0036)", () => {
  before(() => ensureFixtures());

  test("unset + loopback Host: request-derived base (zero-config dev unchanged)", async () => {
    const { server, port } = await boot();
    try {
      const { status, body } = await get(port, "/leftpad-lite");
      assert.equal(status, 200);
      assert.ok(body.includes(`http://127.0.0.1:${port}/leftpad-lite/-/leftpad-lite-`));
    } finally { server.close(); }
  });

  test("unset + non-loopback Host: 421 telling the operator to set SENTINEL_PUBLIC_BASE_URL", async () => {
    const { server, port } = await boot();
    try {
      const { status, body } = await get(port, "/leftpad-lite", "registry.evil.example");
      assert.equal(status, 421);
      assert.match(body, /SENTINEL_PUBLIC_BASE_URL/);
    } finally { server.close(); }
  });

  test("set: configured base wins, spoofed Host is ignored", async () => {
    const { server, port } = await boot("https://sentinel.corp.example");
    try {
      const { status, body } = await get(port, "/leftpad-lite", "registry.evil.example");
      assert.equal(status, 200);
      assert.ok(body.includes("https://sentinel.corp.example/leftpad-lite/-/leftpad-lite-"));
      assert.ok(!body.includes("registry.evil.example"));
    } finally { server.close(); }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/public-base-url-e2e.test.ts`
Expected: FAIL — test 2 gets `200` with `http://registry.evil.example/...` in the body (the vulnerability, demonstrated), test 3 gets request-derived URLs instead of the configured base. Test 1 passes already.

- [ ] **Step 3: Implement publicBaseUrl + loopback fallback**

In `packages/proxy/src/server.ts`:

Add to the import block from `./upstream.js`'s sibling (new import line after the `authz` import at line 41):

```typescript
import { isLoopbackHost } from "./net-config.js";
```

Add to `ServerOptions` (after `vulnerabilities?` at line 77):

```typescript
  /** Public base URL for rewritten dist.tarball links (ADR-0036). Undefined ⇒ loopback-Host-derived only. */
  publicBaseUrl?: string;
```

Add a module-level helper after `mapPool` (line 107):

```typescript
/**
 * Base URL for rewritten dist.tarball links: the configured public base, or a
 * loopback-Host-derived fallback for zero-config local dev. A non-loopback
 * Host with no configured base is refused — the rewrite would otherwise point
 * npm at whatever origin the Host header claims (ADR-0036).
 */
function baseUrlFor(req: Request, configured: string | undefined): string {
  if (configured) return configured;
  const host = req.get("host") ?? "";
  if (isLoopbackHost(host)) return `${req.protocol}://${host}`;
  throw new HttpError(421, `refusing to derive tarball URLs from non-loopback Host "${host}" — set SENTINEL_PUBLIC_BASE_URL`);
}
```

In `createServer`, add a local beside the other option reads (after line 119 `const vulnerabilities = ...`):

```typescript
  const publicBaseUrl = opts.publicBaseUrl;
```

Replace line 613:

```typescript
      const base = `${req.protocol}://${req.get("host")}`;
```

with:

```typescript
      const base = baseUrlFor(req, publicBaseUrl);
```

(The line is already inside the packument route's `try { … } catch (err) { return sendError(res, err); }`, and `sendError` maps `HttpError` to its status — so the 421 needs no extra plumbing. Both the private and public packument branches use this same `base`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/public-base-url-e2e.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 5: Run the packument-touching regression tests**

Run: `node --import tsx --test packages/proxy/test/proxy.test.ts packages/proxy/test/private-serve.test.ts packages/proxy/test/enforce-e2e.test.ts`
Expected: PASS — every existing test drives the server via `127.0.0.1`/`localhost`, which is exactly the preserved loopback fallback.

- [ ] **Step 6: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/test/public-base-url-e2e.test.ts
git commit -m "feat(phase23): SENTINEL_PUBLIC_BASE_URL option — stop trusting inbound Host for tarball rewrites (ADR-0036)"
```

---

### Task 4: Fail-closed env wiring in index.ts

**Files:**
- Modify: `packages/proxy/src/index.ts` — `buildUpstream` (line 39), new `resolveTarballOrigins`/`resolvePublicBaseUrl`, `main()` (line 143)
- Test: `packages/proxy/test/net-startup.test.ts`

**Interfaces:**
- Consumes: `parseTarballOrigins`, `parsePublicBaseUrl` from `./net-config.js` (Task 1); `NpmUpstream(registry, tarballOrigins)` (Task 2); `ServerOptions.publicBaseUrl` (Task 3).
- Produces: env contract — `SENTINEL_TARBALL_ORIGINS` (comma-separated extra origins), `SENTINEL_PUBLIC_BASE_URL`; set-but-invalid ⇒ FATAL exit 1.

- [ ] **Step 1: Write the failing test**

Child-process boot tests, same pattern as `advisories-config.test.ts` (async `execFile`, `SENTINEL_BOOT_EXIT`):

```typescript
// packages/proxy/test/net-startup.test.ts
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

// FATAL-exit posture for the Phase 23 env vars (parity with SENTINEL_AUTH_PUBKEY /
// SENTINEL_ADVISORIES): set-but-invalid must refuse to boot, valid must boot.
describe("proxy boot with SENTINEL_TARBALL_ORIGINS / SENTINEL_PUBLIC_BASE_URL (child process)", () => {
  ensureFixtures();

  function bootWith(extra: Record<string, string>): Promise<{ code: number; stderr: string }> {
    const env = { ...process.env, SENTINEL_UPSTREAM: "fixtures", SENTINEL_BOOT_EXIT: "1", SENTINEL_PORT: "0" };
    delete env.SENTINEL_TARBALL_ORIGINS;
    delete env.SENTINEL_PUBLIC_BASE_URL;
    Object.assign(env, extra);
    return execFileAsync("npx", ["tsx", ENTRY], { cwd: REPO_ROOT, env, timeout: 20_000 })
      .then(({ stderr }) => ({ code: 0, stderr }))
      .catch((err) => ({ code: typeof err.code === "number" ? err.code : 1, stderr: String(err.stderr ?? "") }));
  }

  test("origin entry with a path → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_TARBALL_ORIGINS: "https://cdn.example.com/tarballs" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("non-http origin entry → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_TARBALL_ORIGINS: "ftp://cdn.example.com" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("malformed public base URL → FATAL, non-zero exit", async () => {
    const { code, stderr } = await bootWith({ SENTINEL_PUBLIC_BASE_URL: "not a url" });
    assert.notEqual(code, 0);
    assert.match(stderr, /FATAL/);
  });

  test("valid values for both → boots, exit 0", async () => {
    const { code } = await bootWith({
      SENTINEL_TARBALL_ORIGINS: "https://cdn.example.com",
      SENTINEL_PUBLIC_BASE_URL: "https://sentinel.corp.example",
    });
    assert.equal(code, 0);
  });

  test("both unset → boots, exit 0 (zero behavior change)", async () => {
    const { code } = await bootWith({});
    assert.equal(code, 0);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/net-startup.test.ts`
Expected: FAIL — the three FATAL cases exit 0 (the env vars are silently ignored today). The two boots-fine cases pass already.

- [ ] **Step 3: Implement the env wiring**

In `packages/proxy/src/index.ts`:

Add the import (beside the `validateAuthPublicKey` import at line 4):

```typescript
import { parseTarballOrigins, parsePublicBaseUrl } from "./net-config.js";
```

Change `buildUpstream` (line 39) to accept and thread the allowlist:

```typescript
function buildUpstream(tarballOrigins: readonly string[]): Upstream {
  const mode = env("SENTINEL_UPSTREAM", "npm");
  if (mode === "fixtures" || mode.startsWith("fixtures:")) {
    const dir = mode.includes(":")
      ? resolve(mode.split(":")[1] ?? "")
      : resolve(env("SENTINEL_FIXTURES", "fixtures"));
    return new LocalFixtureUpstream(dir);
  }
  return new NpmUpstream(env("SENTINEL_REGISTRY", "https://registry.npmjs.org"), tarballOrigins);
}
```

Add the two resolvers (beside `resolveVulnerabilities`, after line 130):

```typescript
function resolveTarballOrigins(): string[] {
  const raw = process.env.SENTINEL_TARBALL_ORIGINS;
  if (!raw) return [];
  try {
    return parseTarballOrigins(raw);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}

function resolvePublicBaseUrl(): string | undefined {
  const raw = process.env.SENTINEL_PUBLIC_BASE_URL;
  if (!raw) return undefined;
  try {
    return parsePublicBaseUrl(raw);
  } catch (err) {
    console.error(`FATAL: ${(err as Error).message}`);
    process.exit(1);
  }
}
```

In `main()` (line 143): replace `const upstream = buildUpstream();` with

```typescript
  const tarballOrigins = resolveTarballOrigins();
  const publicBaseUrl = resolvePublicBaseUrl();
  const upstream = buildUpstream(tarballOrigins);
```

Add `publicBaseUrl` to the `createServer({ … })` options object (line 163), and add two startup log lines beside the existing ones (after the `  upstream :` line):

```typescript
    console.log(`  tarball-origins: registry origin${tarballOrigins.length ? " + " + tarballOrigins.join(", ") : " only"}`);
    console.log(`  public-url: ${publicBaseUrl ?? "loopback-derived (set SENTINEL_PUBLIC_BASE_URL for network deployments)"}`);
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --import tsx --test packages/proxy/test/net-startup.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/index.ts packages/proxy/test/net-startup.test.ts
git commit -m "feat(phase23): fail-closed startup parsing for SENTINEL_TARBALL_ORIGINS + SENTINEL_PUBLIC_BASE_URL (ADR-0036)"
```

---

### Task 5: ADR-0036 + docs + full gate

**Files:**
- Create: `docs/adr/0036-network-trust-boundary.md`
- Modify: `docs/adr/README.md` (append an index line in the existing format)
- Modify: `ARCHITECTURE.md` (Phase 23 paragraph, following the Phase 22 paragraph's placement/style)
- Modify: `CLAUDE.md` (Phase 23 paragraph after the Phase 22 one; env vars mentioned in the Stack section; test-count note in Build/test/run)
- Modify: `README.md` (env-var table rows)

**Interfaces:**
- Consumes: everything above (documents the shipped behavior — write the docs from the actual code, not from memory).
- Produces: the merged phase's documentation trail.

- [ ] **Step 1: Write ADR-0036**

```markdown
# ADR-0036: Network trust boundary — tarball origin pinning + configured public base URL

Date: 2026-07-09
Status: Accepted

## Context

An external security audit surfaced two ways the proxy trusts a value an
attacker can influence at its network boundary:

1. **Outbound (SSRF).** `NpmUpstream.getTarball` fetched whatever URL the
   packument's `dist.tarball` claimed. A poisoned packument — or a
   compromised/custom upstream registry — could make the proxy request
   internal services or cloud metadata endpoints from the proxy host.
2. **Inbound (Host-header trust).** The packument rewrite built tarball URLs
   from `req.protocol` + `req.get("host")`. Behind a reverse proxy, or
   reachable by a client with a spoofed Host, the rewritten `dist.tarball`
   could point npm at an attacker-controlled origin.

The design target is a network-deployed enterprise proxy, so both get
first-class fixes, not documentation.

## Decision

**Outbound: deterministic origin pinning, enforced before any request.**
A tarball URL is fetched only if its protocol is http(s) AND its origin is
the configured registry origin (`SENTINEL_REGISTRY`, default
`https://registry.npmjs.org`) or appears in the optional
`SENTINEL_TARBALL_ORIGINS` allowlist (comma-separated bare origins, for
mirror/CDN-backed private registries). Anything else ⇒ `HttpError(502)` and
the request is **never issued** — there is no DNS or IP surface to reason
about. Parsing is fail-closed at startup: a set-but-invalid allowlist is
FATAL (parity with `SENTINEL_AUTH_PUBKEY`).

**Inbound: `SENTINEL_PUBLIC_BASE_URL`.** When set (validated at startup,
malformed ⇒ FATAL), all packument `dist.tarball` rewrites use it and the
request's Host is ignored. When unset, the base is derived from the request
only for a loopback Host (`localhost`, `127.0.0.0/8`, `[::1]`) — the
zero-config dev case; a non-loopback Host is refused with **421** and an
actionable error. A network deployment cannot silently run in the spoofable
mode.

All parsing/validation lives in a pure module
(`packages/proxy/src/net-config.ts`); enforcement lives at the two boundary
sites (`upstream.ts`, `server.ts`).

## Alternatives considered

- **DNS-resolution / private-IP-range filtering** (the audit's suggested
  direction): rejected — non-deterministic, DNS-rebinding-prone, and
  needless once no packument-controlled origin is ever fetched at all.
- **Always requiring `SENTINEL_PUBLIC_BASE_URL`**: rejected — breaks
  zero-config `npm install --registry http://localhost:4873` local dev for
  no security gain (loopback Host is not attacker-controlled in that
  scenario).
- **Trusting `X-Forwarded-*` headers**: rejected — spoofable without a
  trusted-proxy configuration; may be revisited alongside rate limiting
  (ADR-0037).

## Consequences

- A poisoned packument can no longer steer the proxy's outbound fetches;
  scoring and caching are untouched (invariants #1–#4), and the packument
  passthrough still rewrites only `dist.tarball` (invariant #5).
- Deployments serving non-loopback clients must set
  `SENTINEL_PUBLIC_BASE_URL` (breaking for anyone who relied on
  Host-derived URLs over the network — that reliance was the vulnerability).
- Custom registries that serve tarballs from a different origin than their
  packument API need `SENTINEL_TARBALL_ORIGINS`.
```

- [ ] **Step 2: Update the doc set**

- `docs/adr/README.md`: append an ADR-0036 index line matching the file's existing format (read it first).
- `ARCHITECTURE.md`: add a Phase 23 paragraph where the Phase 22 one sits, same style — what shipped, the two env vars, the never-fetch-disallowed-origins and loopback-fallback rules, ADR-0036 reference.
- `CLAUDE.md`: add the Phase 23 paragraph after Phase 22's (matching the established per-phase summary voice); mention `SENTINEL_PUBLIC_BASE_URL`/`SENTINEL_TARBALL_ORIGINS` in the Stack & versions section beside `SENTINEL_VULNERABILITIES`; update the test-count comment in Build/test/run with the real number from Step 3's run.
- `README.md`: add both env vars to the env-var table (read the table first and match its columns).

- [ ] **Step 3: Full gate**

Run: `npm run build`
Expected: clean (no tsc errors).

Run: `npm test`
Expected: all green — previous 546 on darwin plus the new Phase 23 tests (net-config ~20 subtests, tarball-origin 3, public-base-url 3, net-startup 5). Record the actual total for the CLAUDE.md count.

- [ ] **Step 4: Commit**

```bash
git add docs/adr/0036-network-trust-boundary.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase23): ADR-0036 network trust boundary; ARCHITECTURE/CLAUDE/README"
```

---

## Self-review notes

- **Spec coverage:** origin pinning + allowlist (Task 2), fail-closed allowlist parsing (Tasks 1/4), public base URL + loopback fallback + 421 (Task 3), fail-closed base-URL parsing (Task 4), all three spec'd test groups present (poisoned packument never fetched — canary listener; malformed env ⇒ FATAL; Host-spoof matrix), ADR-0036 with the rejected IP-filtering alternative (Task 5). Attestations fetch needs no change (URL built from registry origin) — verified in `upstream.ts:106-117`.
- **Type consistency:** `parseTarballOrigins`/`parsePublicBaseUrl`/`isLoopbackHost`/`assertAllowedTarballUrl` names and signatures match across Tasks 1→4; `NpmUpstream(registry, tarballOrigins)` matches between Tasks 2 and 4; `publicBaseUrl` option name matches between Tasks 3 and 4.
- **Not in scope (later phases):** tree caps, tarball byte caps, coalescing, rate limiting (Phase 24 / ADR-0037); sandbox rework (Phase 25 / ADR-0038).

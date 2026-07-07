# Phase 12 — Control-Plane Authentication & Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Authenticate + authorize the gate-mutating proxy endpoints with signed Ed25519 role tokens (operator/agent/publisher), opt-in via config, so Phase 11's "agent may request, not grant" boundary is enforced at the HTTP layer.

**Architecture:** A pure `packages/core/src/auth.ts` mints/verifies `base64url(payload).base64url(ed25519-sig)` tokens on the existing `edSign`/`edVerify`. A proxy `authz.ts` factory produces a `requireRole([...])` middleware that is a pass-through when no pubkey is configured and a 401/403 gate when one is. A `sentinel token` CLI mints tokens; MCP + script-shell attach `SENTINEL_AUTH_TOKEN`; the dashboard gets a paste-once operator-token field.

**Tech Stack:** Node 24 / TypeScript / npm workspaces; NO new dependencies (all crypto is `node:crypto` Ed25519, reused from ADR-0014).

## Global Constraints

- **Opt-in (load-bearing):** auth is OFF unless `SENTINEL_AUTH_PUBKEY` (a PEM path) is configured. Off ⇒ `requireRole` is a pass-through and every existing test + the demo run unchanged (no edits to the ~300 existing tests). On ⇒ mutating endpoints require a valid role token. Mirrors the signed-policy pattern.
- **Reads stay open always** — all `GET` + the tarball + packument paths are never gated (ADR-0005 npm-facing transparency).
- **Role → endpoint map:** `operator` → `POST /-/approvals`, `DELETE /-/approvals/:integrity`, `DELETE /-/violations/:integrity`; `agent` → `POST /-/approval-requests`, `POST /-/violations`; `publisher` → `PUT /:pkg` (when auth enabled; legacy `SENTINEL_PUBLISH_TOKENS` only in open mode).
- **401 vs 403:** missing / malformed / bad-signature / expired token → **401**; valid token, wrong role → **403**.
- **Expiry IS enforced** (request-time auth is clock-dependent by nature; `now` is an explicit input to sign/verify for test determinism — this is not scoring, invariant #1 does not apply).
- **Token format:** `base64url(payloadJson).base64url(ed25519Sig)`, `payload = { role, sub, iat, exp }` (unix seconds), sig = `edSign` over the base64url payload-segment bytes.
- **Roles:** `type Role = "operator" | "agent" | "publisher"`.
- **Fail-closed clients:** the MCP/script-shell clients attach the token and, on a 401/403, surface it explicitly (MCP tool error) or swallow it (script-shell best-effort report) — never fabricate success (invariant #6).
- ESM only, NodeNext: internal imports use `.js` specifiers even from `.ts`.
- Tests hermetic: in-test Ed25519 keypair + in-process proxy; never hit live npm.
- CLI keypair naming follows the existing `policy keygen` convention: `--out <prefix>` → `<prefix>.pub.pem` + `<prefix>.key.pem`.
- If `rm` of build artifacts fails with EPERM, use `npx tsc --build --force packages/<pkg>`.
- Run all commands from repo root: `/Users/tonibergholm/Developer/claude/pkg-registry`.

---

### Task 1: Core `auth.ts` — token mint + verify

**Files:**
- Create: `packages/core/src/auth.ts`
- Modify: `packages/core/src/index.ts` (export)
- Test: `packages/core/test/auth.test.ts`

**Interfaces:**
- Produces (used by Tasks 2–5):
  - `type Role = "operator" | "agent" | "publisher"`
  - `interface TokenPayload { role: Role; sub: string; iat: number; exp: number }`
  - `signToken(input: { role: Role; sub: string; ttlSeconds: number }, privateKeyPem: string, now?: number): string` (now = unix seconds, defaults to `Math.floor(Date.now()/1000)`)
  - `verifyToken(token: string, publicKeyPem: string, now?: number): { ok: true; role: Role; sub: string; exp: number } | { ok: false; reason: "malformed" | "bad-signature" | "expired" | "bad-role" }`

- [ ] **Step 1: Write the failing test** (`packages/core/test/auth.test.ts`)

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeypair } from "../src/policy.js";
import { signToken, verifyToken } from "../src/auth.js";

const { publicKey, privateKey } = generateKeypair();
const NOW = 1_000_000; // fixed unix seconds for determinism

describe("auth tokens", () => {
  test("round-trips a role token", () => {
    const t = signToken({ role: "operator", sub: "alice", ttlSeconds: 3600 }, privateKey, NOW);
    const r = verifyToken(t, publicKey, NOW + 10);
    assert.equal(r.ok, true);
    if (r.ok) { assert.equal(r.role, "operator"); assert.equal(r.sub, "alice"); assert.equal(r.exp, NOW + 3600); }
  });

  test("each role verifies", () => {
    for (const role of ["operator", "agent", "publisher"] as const) {
      const t = signToken({ role, sub: "x", ttlSeconds: 60 }, privateKey, NOW);
      const r = verifyToken(t, publicKey, NOW);
      assert.equal(r.ok && r.role, role);
    }
  });

  test("a tampered payload is bad-signature", () => {
    const t = signToken({ role: "agent", sub: "x", ttlSeconds: 60 }, privateKey, NOW);
    const s = t.split(".")[1];
    const forged = Buffer.from(JSON.stringify({ role: "operator", sub: "x", iat: NOW, exp: NOW + 60 })).toString("base64url");
    const r = verifyToken(`${forged}.${s}`, publicKey, NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "bad-signature");
  });

  test("an expired token is expired", () => {
    const t = signToken({ role: "operator", sub: "x", ttlSeconds: 60 }, privateKey, NOW);
    const r = verifyToken(t, publicKey, NOW + 61);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "expired");
  });

  test("a token from a different key is bad-signature", () => {
    const other = generateKeypair();
    const t = signToken({ role: "operator", sub: "x", ttlSeconds: 60 }, other.privateKey, NOW);
    const r = verifyToken(t, publicKey, NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "bad-signature");
  });

  test("garbage is malformed", () => {
    assert.equal(verifyToken("not-a-token", publicKey, NOW).ok, false);
    const r = verifyToken("not-a-token", publicKey, NOW);
    if (!r.ok) assert.equal(r.reason, "malformed");
  });

  test("an unknown role is bad-role", async () => {
    // hand-sign a payload with an invalid role using the raw primitives (ESM import, no require)
    const { createPrivateKey, sign } = await import("node:crypto");
    const payload = Buffer.from(JSON.stringify({ role: "root", sub: "x", iat: NOW, exp: NOW + 60 })).toString("base64url");
    const sig = sign(null, Buffer.from(payload), createPrivateKey(privateKey)).toString("base64url");
    const r = verifyToken(`${payload}.${sig}`, publicKey, NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "bad-role");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/core/test/auth.test.ts
```

Expected: FAIL — cannot find module `../src/auth.js`.

- [ ] **Step 3: Implement `packages/core/src/auth.ts`**

```ts
import { Buffer } from "node:buffer";
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";

export type Role = "operator" | "agent" | "publisher";
const ROLES: readonly Role[] = ["operator", "agent", "publisher"];

export interface TokenPayload {
  role: Role;
  sub: string;
  iat: number; // unix seconds
  exp: number; // unix seconds
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Mint a signed role token: base64url(payload).base64url(ed25519 sig over the payload segment). */
export function signToken(
  input: { role: Role; sub: string; ttlSeconds: number },
  privateKeyPem: string,
  now: number = nowSeconds(),
): string {
  const payload: TokenPayload = { role: input.role, sub: input.sub, iat: now, exp: now + input.ttlSeconds };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = edSign(null, Buffer.from(payloadB64), createPrivateKey(privateKeyPem)).toString("base64url");
  return `${payloadB64}.${sig}`;
}

/**
 * Verify a role token offline against a public key. Pure/total: never throws.
 * Order: signature (a tampered payload ⇒ bad-signature) → parse → role → expiry.
 */
export function verifyToken(
  token: string,
  publicKeyPem: string,
  now: number = nowSeconds(),
): { ok: true; role: Role; sub: string; exp: number } | { ok: false; reason: "malformed" | "bad-signature" | "expired" | "bad-role" } {
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: "malformed" };
  const [payloadB64, sigB64] = parts;
  let okSig = false;
  try {
    okSig = edVerify(null, Buffer.from(payloadB64), createPublicKey(publicKeyPem), Buffer.from(sigB64, "base64url"));
  } catch {
    return { ok: false, reason: "bad-signature" };
  }
  if (!okSig) return { ok: false, reason: "bad-signature" };
  let payload: TokenPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as TokenPayload;
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (!ROLES.includes(payload.role)) return { ok: false, reason: "bad-role" };
  if (typeof payload.exp !== "number" || now >= payload.exp) return { ok: false, reason: "expired" };
  return { ok: true, role: payload.role, sub: String(payload.sub ?? ""), exp: payload.exp };
}
```

- [ ] **Step 4: Export from `packages/core/src/index.ts`** — append:

```ts
export { signToken, verifyToken, type Role, type TokenPayload } from "./auth.js";
```

- [ ] **Step 5: Run the test + build**

```bash
npx tsx --test packages/core/test/auth.test.ts
npm run build
```

Expected: PASS (7 tests).

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/auth.ts packages/core/src/index.ts packages/core/test/auth.test.ts
git commit -m "feat(phase12): core auth — Ed25519 signed role tokens (signToken/verifyToken)"
```

---

### Task 2: CLI `sentinel token` (keygen / mint / verify)

**Files:**
- Modify: `packages/cli/src/index.ts` (add the `token` command group)
- Test: `packages/cli/test/token.test.ts`

**Interfaces:**
- Consumes: `signToken`, `verifyToken`, `generateKeypair` from `@sentinel/core`.
- Produces: a `sentinel token` command group with `keygen`/`mint`/`verify` subcommands.

- [ ] **Step 1: Write the failing test** (`packages/cli/test/token.test.ts`) — drive the built CLI over a temp dir:

```ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test } from "node:test";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "src", "index.ts");
const run = (args: string[]) => execFileSync("npx", ["tsx", CLI, ...args], { encoding: "utf8" });

describe("sentinel token", () => {
  test("keygen → mint → verify round-trips", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-tok-"));
    const prefix = join(dir, "auth");
    run(["token", "keygen", "--out", prefix]);
    assert.ok(existsSync(`${prefix}.pub.pem`) && existsSync(`${prefix}.key.pem`));
    const token = run(["token", "mint", "--role", "operator", "--sub", "alice", "--ttl", "3600", "--key", `${prefix}.key.pem`]).trim();
    assert.match(token, /^[\w-]+\.[\w-]+$/);
    const out = run(["token", "verify", token, "--pubkey", `${prefix}.pub.pem`]);
    assert.match(out, /operator/);
    assert.match(out, /alice/);
  });

  test("verify of a garbage token reports the rejection (non-zero exit)", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-tok-"));
    const prefix = join(dir, "auth");
    run(["token", "keygen", "--out", prefix]);
    assert.throws(() => run(["token", "verify", "not-a-token", "--pubkey", `${prefix}.pub.pem`]));
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/cli/test/token.test.ts
```

Expected: FAIL — unknown command `token`.

- [ ] **Step 3: Add the `token` command group to `packages/cli/src/index.ts`** — near the `policyCmd` block. Add `signToken, verifyToken, type Role` to the existing `@sentinel/core` import. Then:

```ts
const tokenCmd = program.command("token").description("Mint and verify signed control-plane auth tokens.");

tokenCmd
  .command("keygen")
  .description("Generate an Ed25519 keypair (PEM) for signing auth tokens.")
  .requiredOption("--out <prefix>", "write <prefix>.pub.pem and <prefix>.key.pem")
  .action((opts: { out: string }) => {
    const { publicKey, privateKey } = generateKeypair();
    writeFileSync(`${opts.out}.pub.pem`, publicKey);
    writeFileSync(`${opts.out}.key.pem`, privateKey);
    console.log(`wrote ${opts.out}.pub.pem and ${opts.out}.key.pem`);
  });

tokenCmd
  .command("mint")
  .description("Mint a signed role token (prints to stdout).")
  .requiredOption("--role <role>", "operator | agent | publisher")
  .requiredOption("--sub <id>", "subject identity recorded in the token")
  .requiredOption("--ttl <seconds>", "seconds until the token expires")
  .requiredOption("--key <privkey>", "path to the Ed25519 private key PEM")
  .action((opts: { role: string; sub: string; ttl: string; key: string }) => {
    const roles = ["operator", "agent", "publisher"];
    if (!roles.includes(opts.role)) {
      console.error(`sentinel: --role must be one of ${roles.join(", ")}`);
      process.exit(2);
    }
    const token = signToken({ role: opts.role as Role, sub: opts.sub, ttlSeconds: Number(opts.ttl) }, readFileSync(opts.key, "utf8"));
    console.log(token);
  });

tokenCmd
  .command("verify")
  .description("Verify a token and print its role/sub/exp, or the rejection reason.")
  .argument("<token>")
  .requiredOption("--pubkey <pubkey>", "path to the Ed25519 public key PEM")
  .action((token: string, opts: { pubkey: string }) => {
    const r = verifyToken(token, readFileSync(opts.pubkey, "utf8"));
    if (r.ok) {
      console.log(`valid  role=${r.role}  sub=${r.sub}  exp=${new Date(r.exp * 1000).toISOString()}`);
    } else {
      console.error(`invalid: ${r.reason}`);
      process.exit(2);
    }
  });
```

(Confirm `writeFileSync`/`readFileSync` are already imported in index.ts — they are, used by `policy` commands.)

- [ ] **Step 4: Run the test + build**

```bash
npm run build
npx tsx --test packages/cli/test/token.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/index.ts packages/cli/test/token.test.ts
git commit -m "feat(phase12): sentinel token CLI (keygen/mint/verify)"
```

---

### Task 3: Proxy `authz.ts` — `requireRole` middleware factory

**Files:**
- Create: `packages/proxy/src/authz.ts`
- Test: `packages/proxy/test/authz-unit.test.ts`

**Interfaces:**
- Consumes: `verifyToken`, `type Role` from `@sentinel/core`.
- Produces (used by Task 4): `makeAuthz(publicKeyPem: string | undefined): { enabled: boolean; requireRole(roles: Role[]): RequestHandler }`. When `publicKeyPem` is undefined, `enabled=false` and `requireRole` returns a pass-through `(req,res,next)=>next()`. When defined: parse `Authorization: Bearer <token>`; no/!bearer → 401; `verifyToken` fail → 401 (reason in the body); role ∉ allowed → 403.

- [ ] **Step 1: Write the failing test** (`packages/proxy/test/authz-unit.test.ts`) — drive the middleware with fake req/res:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeypair, signToken, type Role } from "@sentinel/core";
import { makeAuthz } from "../src/authz.js";

const { publicKey, privateKey } = generateKeypair();
const tok = (role: Role) => signToken({ role, sub: "x", ttlSeconds: 3600 }, privateKey);

function fakeRes() {
  return { statusCode: 200, body: undefined as unknown, status(c: number) { this.statusCode = c; return this; }, json(b: unknown) { this.body = b; return this; } };
}
function call(mw: (req: any, res: any, next: () => void) => void, authHeader?: string) {
  const req = { headers: authHeader ? { authorization: authHeader } : {} };
  const res = fakeRes();
  let nexted = false;
  mw(req, res, () => { nexted = true; });
  return { nexted, status: res.statusCode };
}

describe("makeAuthz", () => {
  test("disabled (no key): requireRole is a pass-through", () => {
    const az = makeAuthz(undefined);
    assert.equal(az.enabled, false);
    assert.equal(call(az.requireRole(["operator"])).nexted, true);
  });

  test("enabled: no token → 401", () => {
    const az = makeAuthz(publicKey);
    const r = call(az.requireRole(["operator"]));
    assert.equal(r.nexted, false);
    assert.equal(r.status, 401);
  });

  test("enabled: operator token on operator route → next", () => {
    const az = makeAuthz(publicKey);
    assert.equal(call(az.requireRole(["operator"]), `Bearer ${tok("operator")}`).nexted, true);
  });

  test("enabled: agent token on operator route → 403", () => {
    const az = makeAuthz(publicKey);
    const r = call(az.requireRole(["operator"]), `Bearer ${tok("agent")}`);
    assert.equal(r.nexted, false);
    assert.equal(r.status, 403);
  });

  test("enabled: a bad token → 401", () => {
    const az = makeAuthz(publicKey);
    assert.equal(call(az.requireRole(["operator"]), "Bearer garbage").status, 401);
  });

  test("enabled: a non-Bearer header → 401", () => {
    const az = makeAuthz(publicKey);
    assert.equal(call(az.requireRole(["operator"]), `Basic ${tok("operator")}`).status, 401);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/authz-unit.test.ts
```

Expected: FAIL — cannot find module `../src/authz.js`.

- [ ] **Step 3: Implement `packages/proxy/src/authz.ts`**

```ts
import type { Request, Response, RequestHandler } from "express";
import { verifyToken, type Role } from "@sentinel/core";

/** Build the authz layer. `publicKeyPem` undefined ⇒ auth disabled (pass-through). */
export function makeAuthz(publicKeyPem: string | undefined): { enabled: boolean; requireRole(roles: Role[]): RequestHandler } {
  const enabled = Boolean(publicKeyPem);

  function requireRole(roles: Role[]): RequestHandler {
    if (!enabled) return (_req, _res, next) => next();
    return (req: Request, res: Response, next: () => void) => {
      const header = req.headers.authorization;
      if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "authentication required (Bearer token)" });
      }
      const result = verifyToken(header.slice("Bearer ".length).trim(), publicKeyPem!);
      if (!result.ok) {
        return res.status(401).json({ error: `invalid token: ${result.reason}` });
      }
      if (!roles.includes(result.role)) {
        return res.status(403).json({ error: `role ${result.role} not permitted (need ${roles.join(" or ")})` });
      }
      next();
    };
  }

  return { enabled, requireRole };
}
```

- [ ] **Step 4: Run the test + build**

```bash
npm run build
npx tsx --test packages/proxy/test/authz-unit.test.ts
```

Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/src/authz.ts packages/proxy/test/authz-unit.test.ts
git commit -m "feat(phase12): proxy authz — requireRole middleware factory (401/403, opt-in)"
```

---

### Task 4: Wire authz into the server + publish migration + role matrix e2e

**Files:**
- Modify: `packages/proxy/src/server.ts` (ServerOptions, build authz, apply requireRole, publish migration)
- Modify: `packages/proxy/src/index.ts` (resolve `SENTINEL_AUTH_PUBKEY`, pass `authPublicKey`)
- Test: `packages/proxy/test/authz-e2e.test.ts`

**Interfaces:**
- Consumes: `makeAuthz` (Task 3), `signToken` (Task 1).
- Produces: `ServerOptions.authPublicKey?: string` (PEM string; undefined ⇒ open mode). The six mutating routes gated per the role map. `PUT /:pkg` uses `requireRole(["publisher"])` when auth is enabled, else the legacy `requirePublishAuth`.

- [ ] **Step 1: Write the failing e2e test** (`packages/proxy/test/authz-e2e.test.ts`)

```ts
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, generateKeypair, signToken, type AuditReport, type Role } from "@sentinel/core";
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

const { publicKey, privateKey } = generateKeypair();
const tok = (role: Role) => signToken({ role, sub: "test", ttlSeconds: 3600 }, privateKey);

function boot(authPublicKey?: string): Promise<{ server: Server; base: string }> {
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
    approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY, policy: "block",
    privateStore: new PrivatePackageStore(), violations: new ViolationStore(),
    approvalRequests: new ApprovalRequestStore(), authPublicKey,
  });
  return new Promise((r) => { const server = app.listen(0, () => r({ server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}` })); });
}
async function integrityOf(base: string, pkg: string, v: string): Promise<string> {
  return ((await (await fetch(`${base}/-/audit/${pkg}/${v}`)).json()) as AuditReport).meta.integrity!;
}

describe("control-plane auth (enabled)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot(publicKey)); });
  after(() => server?.close());

  test("reads stay open with no token", async () => {
    assert.equal((await fetch(`${base}/-/audit/leftpad-lite/1.0.0`)).status, 200);
  });

  test("POST /-/approvals with no token → 401", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 401);
  });

  test("POST /-/approvals with an operator token → 200", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("operator")}` }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 200);
  });

  test("POST /-/approvals with an AGENT token → 403 (Phase 11 boundary enforced)", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("agent")}` }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 403);
  });

  test("POST /-/approval-requests with an agent token → 200", async () => {
    const integrity = await integrityOf(base, "net-fetch-lite", "1.0.0");
    const res = await fetch(`${base}/-/approval-requests`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("agent")}` }, body: JSON.stringify({ name: "net-fetch-lite", version: "1.0.0", integrity, reason: "x" }) });
    assert.equal(res.status, 200);
  });

  test("POST /-/violations with an agent token → 200", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/violations`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok("agent")}` }, body: JSON.stringify({ name: "leftpad-lite", version: "1.0.0", integrity, kind: "network", target: null, confidence: "suspected", deniedResource: null, evidence: { exitCode: 1, stderrExcerpt: "x" } }) });
    assert.equal(res.status, 200);
  });

  test("DELETE /-/violations with an agent token → 403 (clear is operator-only)", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/violations/${encodeURIComponent(integrity)}`, { method: "DELETE", headers: { authorization: `Bearer ${tok("agent")}` } });
    assert.equal(res.status, 403);
  });

  test("an expired operator token → 401", async () => {
    const expired = signToken({ role: "operator", sub: "x", ttlSeconds: 60 }, privateKey, 1000); // exp=1060, long past
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${expired}` }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 401);
  });
});

describe("control-plane auth (disabled / open mode)", () => {
  let server: Server; let base: string;
  before(async () => { ensureFixtures(); ({ server, base } = await boot(undefined)); });
  after(() => server?.close());

  test("mutations succeed with NO token when auth is disabled (backward compat)", async () => {
    const integrity = await integrityOf(base, "leftpad-lite", "1.0.0");
    const res = await fetch(`${base}/-/approvals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ integrity, decision: "approved" }) });
    assert.equal(res.status, 200);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/proxy/test/authz-e2e.test.ts
```

Expected: FAIL — `ServerOptions` has no `authPublicKey`; mutations are open so the 401/403 assertions fail.

- [ ] **Step 3: Implement `server.ts`** — import + option + wiring:

```ts
import { makeAuthz } from "./authz.js";
```

Add to `ServerOptions`:

```ts
  /** Operator Ed25519 public key PEM. Undefined ⇒ control-plane auth disabled (open mode). */
  authPublicKey?: string;
```

In `createServer`, after the other option binds: `const authz = makeAuthz(opts.authPublicKey);`

Apply `authz.requireRole([...])` as middleware on the mapped routes. Express allows `app.post(path, mw, handler)` — insert the middleware arg. Concretely:
- `app.post("/-/approvals", authz.requireRole(["operator"]), (req, res) => { … })`
- `app.delete(/^\/-\/approvals\/(.+)$/, authz.requireRole(["operator"]), (req, res) => { … })`
- `app.post("/-/approval-requests", authz.requireRole(["agent"]), (req, res) => { … })`
- `app.post("/-/violations", authz.requireRole(["agent"]), (req, res) => { … })`
- `app.delete(/^\/-\/violations\/(.+)$/, authz.requireRole(["operator"]), (req, res) => { … })`

Publish migration — the existing `app.put(/^\/(.+)$/, requirePublishAuth, jsonPublish, …)`. Replace the auth middleware conditionally: when `authz.enabled`, use `authz.requireRole(["publisher"])`; else keep `requirePublishAuth`. Implement as:

```ts
  const publishAuth = authz.enabled ? authz.requireRole(["publisher"]) : requirePublishAuth;
  app.put(/^\/(.+)$/, publishAuth, jsonPublish, async (req, res) => { … });
```

(Leave the `requirePublishAuth` function defined for open mode.)

- [ ] **Step 4: Wire `index.ts`** — resolve the pubkey (FATAL on unreadable path, mirroring `resolveTrustMaterial`):

```ts
function resolveAuthPublicKey(): string | undefined {
  const path = process.env.SENTINEL_AUTH_PUBKEY;
  if (!path) return undefined; // open mode
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    console.error(`FATAL: cannot read SENTINEL_AUTH_PUBKEY: ${(err as Error).message}`);
    process.exit(1);
  }
}
```

In `main()`: `const authPublicKey = resolveAuthPublicKey();`, pass `authPublicKey` in `createServer({...})`, and add a boot log line: `` console.log(`  auth     : ${authPublicKey ? "enabled (signed role tokens)" : "disabled (open control plane)"}`); ``

- [ ] **Step 5: Build + run the e2e + neighbors**

```bash
npm run build
npx tsx --test packages/proxy/test/authz-e2e.test.ts packages/proxy/test/approvals.test.ts packages/proxy/test/violations-e2e.test.ts packages/proxy/test/approval-requests-e2e.test.ts packages/proxy/test/publish.test.ts
```

Expected: PASS — the existing suites are open-mode (no `authPublicKey`) so they stay green; the new e2e proves the role matrix.

- [ ] **Step 6: Full suite**

```bash
npm test 2>&1 | tail -5
```

Expected: green (record counts).

- [ ] **Step 7: Commit**

```bash
git add packages/proxy/src/server.ts packages/proxy/src/index.ts packages/proxy/test/authz-e2e.test.ts
git commit -m "feat(phase12): gate mutating endpoints with requireRole; SENTINEL_AUTH_PUBKEY; role matrix e2e"
```

---

### Task 5: Client auth — MCP `ProxyClient` + `sentinel-script-shell` attach the token

**Files:**
- Modify: `packages/mcp/src/client.ts` (attach `SENTINEL_AUTH_TOKEN` on POSTs)
- Modify: `packages/cli/src/script-shell.ts` (attach it on the violation-report POST)
- Test: `packages/mcp/test/client-auth.test.ts`

**Interfaces:**
- Consumes: the auth-enabled proxy (Task 4).
- Produces: `ProxyClient` reads `SENTINEL_AUTH_TOKEN` (constructor default from env) and sends `Authorization: Bearer <token>` on `postJson`. `reportViolation` in script-shell attaches the same env token.

- [ ] **Step 1: Write the failing test** (`packages/mcp/test/client-auth.test.ts`) — boot an auth-enabled in-process proxy and drive the client:

```ts
// reuse the in-process-proxy boot boilerplate from client.test.ts, but boot with authPublicKey: publicKey
// and construct ProxyClient with an agent token.
import assert from "node:assert/strict";
// ... imports: generateKeypair, signToken from @sentinel/core; createServer + stores; ProxyClient, ProxyError ...

describe("ProxyClient auth", () => {
  // before(): const {publicKey, privateKey} = generateKeypair(); boot proxy with authPublicKey: publicKey.
  test("with an agent token, a request_approval POST is authorized", async () => {
    const client = new ProxyClient(base, signToken({ role: "agent", sub: "mcp", ttlSeconds: 3600 }, privateKey));
    const rep = await client.audit("net-fetch-lite", "1.0.0");
    await assert.doesNotReject(client.approvalRequest({ name: "net-fetch-lite", version: "1.0.0", integrity: rep.meta.integrity!, reason: "x" }));
  });

  test("with NO token against an auth-enabled proxy, a POST throws ProxyError (401), not a fake success", async () => {
    const client = new ProxyClient(base); // no token
    const rep = await client.audit("net-fetch-lite", "1.0.0");
    await assert.rejects(() => client.approvalRequest({ name: "net-fetch-lite", version: "1.0.0", integrity: rep.meta.integrity!, reason: "x" }), (e) => e instanceof ProxyError && e.status === 401);
  });

  test("reads work with no token (open reads)", async () => {
    const client = new ProxyClient(base);
    assert.equal((await client.audit("leftpad-lite", "1.0.0")).verdict, "allow");
  });
});
```

- [ ] **Step 2: Run to verify it fails**

```bash
npx tsx --test packages/mcp/test/client-auth.test.ts
```

Expected: FAIL — `ProxyClient` constructor takes only a baseUrl; POSTs send no auth header (the agent-token test's `approvalRequest` may pass under open mode, but the no-token-401 test fails because the proxy IS auth-enabled and the client sends nothing → but currently the client can't even be told about auth; the first test fails to compile/authorize).

- [ ] **Step 3: Implement the `ProxyClient` auth header** — change the constructor and `postJson`:

```ts
export class ProxyClient {
  constructor(private readonly baseUrl: string, private readonly authToken: string | undefined = process.env.SENTINEL_AUTH_TOKEN) {}

  // in postJson, add the header when a token is present:
  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = { "content-type": "application/json", accept: "application/json" };
    if (this.authToken) headers.authorization = `Bearer ${this.authToken}`;
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
    } catch (e) {
      throw new ProxyError(`cannot reach Sentinel proxy at ${this.baseUrl}: ${(e as Error).message}`);
    }
    if (!res.ok) throw new ProxyError(`proxy ${path} returned ${res.status}: ${await safeText(res)}`, res.status);
    return (await res.json()) as T;
  }
}
```

(GET requests stay open — no auth header needed on `getJson`.)

- [ ] **Step 4: Implement the script-shell token attach** — in `packages/cli/src/script-shell.ts`, `reportViolation` adds the header:

```ts
async function reportViolation(proxy: string, name: string, version: string, violation: SandboxViolation): Promise<void> {
  try {
    const man = await fetch(`${proxy}/-/manifest/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
    if (!man.ok) return;
    const integrity = ((await man.json()) as { meta?: { integrity?: string } }).meta?.integrity;
    if (!integrity) return;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (process.env.SENTINEL_AUTH_TOKEN) headers.authorization = `Bearer ${process.env.SENTINEL_AUTH_TOKEN}`;
    await fetch(`${proxy}/-/violations`, { method: "POST", headers, body: JSON.stringify({ name, version, integrity, ...violation }) });
  } catch {
    /* telemetry is best-effort: a reporting failure never changes the install outcome */
  }
}
```

- [ ] **Step 5: Run the test + build + neighbors**

```bash
npm run build
npx tsx --test packages/mcp/test/client-auth.test.ts packages/mcp/test/client.test.ts packages/mcp/test/tools.test.ts packages/cli/test/script-shell-report.test.ts
```

Expected: PASS. (The existing mcp/client tests boot open-mode proxies and pass no token — still green.)

- [ ] **Step 6: Commit**

```bash
git add packages/mcp/src/client.ts packages/cli/src/script-shell.ts packages/mcp/test/client-auth.test.ts
git commit -m "feat(phase12): MCP + script-shell attach SENTINEL_AUTH_TOKEN (agent role); reads stay open"
```

---

### Task 6: Dashboard operator-token field

**Files:**
- Modify: `packages/proxy/public/index.html`

**Interfaces:**
- Consumes: the auth-enabled proxy's operator routes (Task 4).

- [ ] **Step 1: Add the operator-token field + a helper** — in `index.html` header, add an `<input id="op-token" placeholder="operator token (if auth enabled)">` whose value persists to `localStorage`. Add a helper that builds mutation headers:

```js
function opHeaders(extra) {
  const h = Object.assign({ "content-type": "application/json" }, extra || {});
  const t = ($("op-token") && $("op-token").value || localStorage.getItem("sentinel-op-token") || "").trim();
  if (t) h.authorization = "Bearer " + t;
  return h;
}
// persist on change:
if ($("op-token")) {
  $("op-token").value = localStorage.getItem("sentinel-op-token") || "";
  $("op-token").addEventListener("change", () => localStorage.setItem("sentinel-op-token", $("op-token").value.trim()));
}
```

- [ ] **Step 2: Route the mutating fetches through `opHeaders`** — the existing Approve/Deny (in `loadApprovals` and the pending-requests panel), the revoke (`data-revoke` in approvals), and the clear-quarantine actions currently `fetch("/-/approvals" | "/-/approvals/:integrity" | "/-/violations/:integrity", { method, headers: {"content-type":"application/json"} })`. Replace each mutation fetch's headers with `opHeaders()` (and for DELETE calls that had no content-type, `opHeaders()` is still fine — an unused content-type header is harmless). Leave all GET/load fetches untouched (reads are open).

- [ ] **Step 3: Boot check (offline, fixtures — open mode, so the field is unused but harmless)**

```bash
npm run build
SENTINEL_UPSTREAM=fixtures SENTINEL_BOOT_EXIT=1 node packages/proxy/dist/index.js
```

Expected: boots and exits clean. (The panel behavior under real auth is covered by Task 4's e2e; this is a static-HTML change.)

- [ ] **Step 4: Full suite (nothing server-side changed)**

```bash
npm test 2>&1 | tail -4
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add packages/proxy/public/index.html
git commit -m "feat(phase12): dashboard operator-token field attaches Bearer auth to control-plane mutations"
```

---

### Task 7: Docs, ADR-0025, final verification

**Files:**
- Create: `docs/adr/0025-control-plane-auth.md`
- Modify: `ARCHITECTURE.md` (auth section + role→endpoint table; §5 if it lists security posture)
- Modify: `CLAUDE.md` (What-this-is phase list; test-count line)
- Modify: `README.md` (the `sentinel token` workflow; `SENTINEL_AUTH_PUBKEY` / `SENTINEL_AUTH_TOKEN` env vars; the role→endpoint table)

- [ ] **Step 1: Write ADR-0025** — follow the house style of `docs/adr/0024-agent-native-mcp-surface.md`. Required content: **Context** (control plane unauthenticated; Phase 11's request-not-grant boundary was honor-system). **Decision** (signed stateless Ed25519 role tokens reusing ADR-0014 machinery; three roles operator/agent/publisher; opt-in via SENTINEL_AUTH_PUBKEY; reads stay open; `requireRole` middleware; the role→endpoint map; publish migrates to `publisher` when auth enabled). **Enforcement of the Phase 11 boundary** (an agent token on POST /-/approvals → 403 — the boundary is now real, not honor-system). **401 vs 403** semantics; **expiry enforced** (request-time auth, not scoring — invariant #1 untouched). **Consequences** (backward compatible — open mode keeps all tests green; stateless — no token store; revocation via short expiry + key rotation). **Deferred** (revocation lists; multi-key rotation-with-overlap; per-endpoint scopes; authenticating reads/tarball; mTLS; dashboard login flow; rate limiting). **Rejected** (opaque-in-store — mutable state, diverges from signed-artifact pattern; HMAC — shared secret collapses operator/agent separation). Extends ADR-0014/0013/0024/0015/0005.

- [ ] **Step 2: ARCHITECTURE.md** — add a control-plane-auth subsection to the client-integration/security area: the opt-in posture, the token format, the role→endpoint table, and the reads-open line. Note that auth enforces the ADR-0013/0024 boundary at the HTTP layer.

- [ ] **Step 3: CLAUDE.md** — add the Phase 12 sentence to "What this is" (mirror Phase 11's density: signed role-token control-plane auth, opt-in via SENTINEL_AUTH_PUBKEY, operator/agent/publisher, enforces the request-not-grant boundary). Update the `npm test` count line with the ACTUAL number from Step 5 (preserve the darwin-skip caveats).

- [ ] **Step 4: README.md** — a "Control-plane authentication" section: the `sentinel token keygen/mint/verify` workflow, the `SENTINEL_AUTH_PUBKEY` (proxy) and `SENTINEL_AUTH_TOKEN` (MCP/script-shell) env vars, the operator-token dashboard field, and the role→endpoint table. State it is opt-in (open by default).

- [ ] **Step 5: Full Definition-of-Done run**

```bash
npm run build
npm run fixtures
npm test 2>&1 | tail -8
npm run demo 2>&1 | tail -3
```

Expected: build clean; ALL tests pass (record exact count for CLAUDE.md); demo still blocks the malicious fixture (demo runs open mode — unaffected). If the count differs from CLAUDE.md, update the doc to reality.

- [ ] **Step 6: Commit**

```bash
git add docs ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase12): ADR-0025 control-plane auth; ARCHITECTURE auth section; CLAUDE/README updates"
```

---

## Self-review notes (already applied)

- **Spec coverage:** §1 architecture (auth.ts, authz.ts, opt-in, role map) → Tasks 1/3/4; §2 token format + sign/verify + CLI → Tasks 1/2; §3 enforcement + MCP/script-shell/dashboard clients → Tasks 4/5/6; §4 testing (core pure, authz-e2e role matrix incl. agent→403 + open-mode backward-compat, CLI round-trip, MCP auth) → Tasks 1–5; docs/DoD → Task 7. Backward-compat guarantee (open mode default) is proven by an explicit test in Task 4 and by the untouched existing suite.
- **Type consistency:** `Role`/`signToken`/`verifyToken` (Task 1) consumed by name in Tasks 2/3/4/5; `makeAuthz(publicKeyPem).requireRole(roles)` (Task 3) → server wiring (Task 4); `ServerOptions.authPublicKey` (Task 4) ← `SENTINEL_AUTH_PUBKEY` (index) and ← every e2e boot; `SENTINEL_AUTH_TOKEN` consistent between ProxyClient (Task 5) and script-shell (Task 5) and README (Task 7).
- **Known judgment calls:** CLI keypair naming follows the existing `policy keygen` `.pub.pem`/`.key.pem` convention (spec said `auth.key`/`auth.pub` — the repo convention is used for consistency, flagged here). Publish keeps its legacy token path in open mode and migrates to the `publisher` role only when auth is enabled (no behavior change for existing publish deployments that don't set a pubkey). Expiry is enforced (request-time auth is clock-dependent by nature — distinct from the surfaced-not-enforced policy-key expiry). Reads (incl. `POST /-/audit-tree`, which is a read-shaped audit fan-out, not a gate mutation) are NOT gated — only the five gate-mutating routes + publish are.

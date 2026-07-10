# Signature & Provenance Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un-flatten the npm signature/provenance signal, verify the registry signature offline (ECDSA P-256/SHA-256/DER, keyid-matched), surface it via a rule, and let policy require signature/provenance — with `invalid` signatures hard-blocking.

**Architecture:** A pure `verifyRegistrySignature` in `@sentinel/core` runs during audit assembly (offline, keys are a static input — never on the request path). `PackageMeta.signatureStatus` becomes precise `signature` + `provenance` fields. A new `provenance` rule surfaces the verified status as findings; a policy gate (`requireSignature`/`requireProvenance`) blocks matched-but-missing packages, mirroring `deny`. Full Sigstore verification is deferred.

**Tech Stack:** Node 24 + TypeScript (NodeNext, ESM, `.js` internal specifiers), `node:crypto` (ECDSA P-256), Express 5, `tar` 7, tests on `node:test` + `tsx`.

## Global Constraints

- ESM only (`"type": "module"`); internal imports use `.js` specifiers even from `.ts`.
- **Invariant #1 (determinism):** `verifyRegistrySignature` is pure — same `(payload, signatures, keys)` ⇒ same verdict.
- **Invariant #3 (cheap sync gate):** verification is offline; signing keys are a static configured input, NEVER fetched at audit time.
- **Invariant #5 (transparent passthrough):** the packument passthrough still rewrites **only** `dist.tarball`; new fields are derived internally, not stripped/synthesized onto the npm doc.
- **Signature crypto is ECDSA P-256, SHA-256, DER encoding** (Node's `crypto.verify` default — NO `dsaEncoding` override). Payload string is exactly `` `${name}@${version}:${integrity}` ``.
- **`SignatureVerdict` = `"verified" | "invalid" | "unsigned" | "unknown"`; `provenance` ∈ `"present" | "absent"`.** `unknown` = a signature exists but no configured key matches its `keyid`.
- **Hermetic tests (CLAUDE.md):** synthetic test keys only; NEVER hit live npm in `npm test`. Malicious fixtures scored as text, never executed.
- **`info`-severity findings have weight 0** in `DEFAULT_POLICY` (`severityWeight.info === 0`) — relied on so `unknown`/`absent` findings never shift a score.
- Build with `npm run build`; if `rm` of `dist/` fails EPERM, use `npx tsc --build --force <pkg>`. Single test file: `node --import tsx --test <path>`. Full suite: `npm test` (baseline this branch: 198 tests / 196 pass / 2 skip on darwin).

---

### Task 1: Offline verification module + new types

**Files:**
- Create: `packages/core/src/signature.ts`
- Modify: `packages/core/src/types.ts` (add `RegistrySignature`, `SignatureVerdict`)
- Modify: `packages/core/src/index.ts` (export the new symbols)
- Test: `packages/core/test/signature.test.ts`

**Interfaces:**
- Produces:
  - `type SignatureVerdict = "verified" | "invalid" | "unsigned" | "unknown"`
  - `interface RegistrySignature { keyid: string; sig: string }` (sig is base64)
  - `interface NpmSigningKey { keyid: string; spkiPem: string; expires: string | null }`
  - `NPM_SIGNING_KEYS: NpmSigningKey[]`
  - `verifyRegistrySignature(payload: { name: string; version: string; integrity: string }, signatures: RegistrySignature[] | null | undefined, keys: NpmSigningKey[]): SignatureVerdict`

- [ ] **Step 1: Write the failing test**

Create `packages/core/test/signature.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateKeyPairSync, sign, createHash } from "node:crypto";
import { verifyRegistrySignature, type NpmSigningKey, type RegistrySignature } from "../src/signature.js";

// A synthetic P-256 key acting like an npm signing key.
const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const spkiPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
const keyid = "SHA256:" + createHash("sha256").update(spkiDer).digest("base64");
const KEYS: NpmSigningKey[] = [{ keyid, spkiPem, expires: null }];

const payload = { name: "demo", version: "1.0.0", integrity: "sha512-abc" };
function signFor(p: typeof payload, kid = keyid): RegistrySignature {
  const sig = sign("sha256", Buffer.from(`${p.name}@${p.version}:${p.integrity}`), privateKey); // DER default
  return { keyid: kid, sig: sig.toString("base64") };
}

describe("verifyRegistrySignature", () => {
  test("verified: a valid signature over the payload against a matching key", () => {
    assert.equal(verifyRegistrySignature(payload, [signFor(payload)], KEYS), "verified");
  });
  test("invalid: signature over a different payload (tamper)", () => {
    const wrong = signFor({ ...payload, integrity: "sha512-EVIL" });
    assert.equal(verifyRegistrySignature(payload, [wrong], KEYS), "invalid");
  });
  test("unsigned: no signatures", () => {
    assert.equal(verifyRegistrySignature(payload, null, KEYS), "unsigned");
    assert.equal(verifyRegistrySignature(payload, [], KEYS), "unsigned");
  });
  test("unknown: signature keyid matches no configured key", () => {
    assert.equal(verifyRegistrySignature(payload, [signFor(payload, "SHA256:nope")], KEYS), "unknown");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/core/test/signature.test.ts`
Expected: FAIL — cannot find module `../src/signature.js`.

- [ ] **Step 3: Write minimal implementation**

Create `packages/core/src/signature.ts`:

```ts
import { Buffer } from "node:buffer";
import { createPublicKey, verify } from "node:crypto";

/** Result of checking a package's registry signature. `unknown` = a signature is
 *  present but no configured key matches its keyid, so we can't assess it. */
export type SignatureVerdict = "verified" | "invalid" | "unsigned" | "unknown";

/** One entry from a packument's `dist.signatures` (npm serves `sig` base64). */
export interface RegistrySignature {
  keyid: string;
  sig: string;
}

/** A trusted registry signing key. `spkiPem` is a SubjectPublicKeyInfo PEM. */
export interface NpmSigningKey {
  keyid: string;
  spkiPem: string;
  expires: string | null;
}

/** Convert npm's base64 SPKI DER key body to a SPKI PEM for `createPublicKey`. */
function derB64ToSpkiPem(b64: string): string {
  const body = b64.replace(/(.{64})/g, "$1\n");
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
}

/**
 * npm's published registry signing keys (`/-/npm/v1/keys`), bundled as a static
 * input. Verified live against the endpoint. Maintained by hand; NOT fetched at
 * audit time (invariant #3). The first key expired 2025-01-29; the second is the
 * current active key (`expires: null`).
 */
export const NPM_SIGNING_KEYS: NpmSigningKey[] = [
  {
    keyid: "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
    spkiPem: derB64ToSpkiPem("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="),
    expires: "2025-01-29T00:00:00.000Z",
  },
  {
    keyid: "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
    spkiPem: derB64ToSpkiPem("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g=="),
    expires: null,
  },
];

/**
 * Offline-verify the npm registry signature over `${name}@${version}:${integrity}`.
 * ECDSA P-256 / SHA-256 / DER (Node default). Pure: same inputs ⇒ same verdict.
 */
export function verifyRegistrySignature(
  payload: { name: string; version: string; integrity: string },
  signatures: RegistrySignature[] | null | undefined,
  keys: NpmSigningKey[],
): SignatureVerdict {
  if (!signatures || signatures.length === 0) return "unsigned";
  const data = Buffer.from(`${payload.name}@${payload.version}:${payload.integrity}`);
  for (const s of signatures) {
    const key = keys.find((k) => k.keyid === s.keyid);
    if (!key) continue;
    try {
      const ok = verify("sha256", data, createPublicKey(key.spkiPem), Buffer.from(s.sig, "base64"));
      return ok ? "verified" : "invalid";
    } catch {
      return "invalid";
    }
  }
  return "unknown";
}
```

In `packages/core/src/index.ts`, add a new export block:
```ts
export {
  verifyRegistrySignature,
  NPM_SIGNING_KEYS,
  type SignatureVerdict,
  type RegistrySignature,
  type NpmSigningKey,
} from "./signature.js";
```

In `packages/core/src/types.ts`, add near the top (after `Severity`), so other modules can import the types from `types.js` too:
```ts
/** Result of verifying a package's npm registry signature. */
export type SignatureVerdict = "verified" | "invalid" | "unsigned" | "unknown";
```
> Keep `RegistrySignature`/`NpmSigningKey` in `signature.ts` (they are verification-module types). `SignatureVerdict` lives in `types.ts` because `PackageMeta` (Task 2) references it; re-export it from `signature.ts` via `export type { SignatureVerdict } from "./types.js";` instead of redefining, so there is ONE definition.

Adjust `signature.ts` accordingly: replace its local `export type SignatureVerdict` with `import type { SignatureVerdict } from "./types.js";` and `export type { SignatureVerdict };`.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --import tsx --test packages/core/test/signature.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/signature.ts packages/core/src/types.ts packages/core/src/index.ts packages/core/test/signature.test.ts
git commit -m "feat(core): verifyRegistrySignature + NPM_SIGNING_KEYS (offline ECDSA P-256/DER)"
```

---

### Task 2: Un-flatten the data model + wire verification

**Files:**
- Modify: `packages/core/src/types.ts` (`PackageMeta`: replace `signatureStatus` with `signature` + `provenance`)
- Modify: `packages/core/src/audit.ts` (`AuditTarballInput`, `runAudit` verify + set fields)
- Modify: `packages/proxy/src/upstream.ts` (`UpstreamVersion`, `normalizeVersion`, `RegistryDoc`, `LocalFixtureUpstream`)
- Modify: `packages/proxy/src/server.ts` (`ServerOptions.signingKeys`, thread into `runAudit`)
- Modify: `packages/cli/src/index.ts` (`scan` meta)
- Modify: `packages/cli/src/format.ts` (display) — full replacement in Task 6; here just make it compile
- Modify: test metas: `packages/core/test/audit.test.ts`, `capabilities.test.ts`, `score.test.ts`, `packages/proxy/test/private-serve.test.ts`
- Test: `packages/core/test/audit.test.ts` (add a field-flow assertion)

**Interfaces:**
- Consumes: `verifyRegistrySignature`, `NPM_SIGNING_KEYS`, `RegistrySignature`, `NpmSigningKey`, `SignatureVerdict` (Task 1).
- Produces:
  - `PackageMeta.signature: SignatureVerdict` and `PackageMeta.provenance: "present" | "absent"` (replacing `signatureStatus`).
  - `AuditTarballInput` gains `signatures?: RegistrySignature[] | null`, `hasProvenance?: boolean`, `signingKeys?: NpmSigningKey[]`.
  - `UpstreamVersion` gains `signatures: RegistrySignature[] | null`, `hasProvenance: boolean` (drops `signatureStatus`).
  - `ServerOptions.signingKeys?: NpmSigningKey[]`.

> **Why the rule comes later:** in this task the fixtures are still unsigned (LocalFixtureUpstream provides `signatures: null`), so `meta.signature` is `"unsigned"`/`"unknown"` — but no rule reads it yet, so verdicts are unchanged and existing tests stay green.

- [ ] **Step 1: Write the failing test**

Add to `packages/core/test/audit.test.ts` (a new test; keep existing ones):

```ts
import { NPM_SIGNING_KEYS } from "../src/index.js";
// ... existing imports ...

test("runAudit populates signature/provenance (unsigned when no signatures)", async () => {
  const tgz = /* an existing fixture tarball buffer used elsewhere in this file */ await someFixtureTarball();
  const audit = await runAudit({
    meta: { name: "demo", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, integrity: "sha512-x" },
    tarball: tgz,
    signatures: null,
    hasProvenance: false,
    signingKeys: NPM_SIGNING_KEYS,
  });
  assert.equal(audit.meta.signature, "unsigned");
  assert.equal(audit.meta.provenance, "absent");
});
```
> Reuse whatever tarball-loading helper this test file already uses; if none, load a fixture `.tgz` via `readFileSync(join(FIXTURES, ".tarballs", "leftpad-lite-1.0.0.tgz"))` with the file's existing `FIXTURES` constant (add one if absent, mirroring `proxy.test.ts`).

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/core/test/audit.test.ts`
Expected: FAIL — `AuditTarballInput` has no `signatures`/`hasProvenance`, and `audit.meta.signature` is undefined.

- [ ] **Step 3: Write minimal implementation**

**`packages/core/src/types.ts`** — in `PackageMeta`, replace:
```ts
  /** npm registry signature / provenance status. */
  signatureStatus: "signed" | "unsigned" | "unknown";
```
with:
```ts
  /** Verified npm registry-signature status. */
  signature: SignatureVerdict;
  /** Whether the packument declares a build-provenance attestation. */
  provenance: "present" | "absent";
```

**`packages/core/src/audit.ts`** — extend imports:
```ts
import { verifyRegistrySignature, NPM_SIGNING_KEYS, type RegistrySignature, type NpmSigningKey } from "./signature.js";
```
Extend `AuditTarballInput`:
```ts
export interface AuditTarballInput {
  meta: Omit<PackageMeta, "integrity" | "unpackedSize" | "fileCount" | "signature" | "provenance"> & {
    integrity?: string | null;
  };
  tarball: Buffer;
  baselineTarball?: Buffer;
  /** Raw `dist.signatures` from the packument (base64 sigs), verified offline. */
  signatures?: RegistrySignature[] | null;
  /** Whether the packument declared `dist.attestations`. */
  hasProvenance?: boolean;
  /** Trusted signing keys (default: bundled npm keys). Never fetched at audit time. */
  signingKeys?: NpmSigningKey[];
}
```
In `runAudit`, after `integrity` is known and before `buildAudit`, compute the fields and add them to `meta`:
```ts
  const integrity = input.meta.integrity ?? integrityOf(input.tarball);
  const signature = verifyRegistrySignature(
    { name: input.meta.name, version: input.meta.version, integrity },
    input.signatures ?? null,
    input.signingKeys ?? NPM_SIGNING_KEYS,
  );
  const meta: PackageMeta = {
    ...input.meta,
    integrity,
    unpackedSize: extracted.unpackedSize,
    fileCount: extracted.fileCount,
    hasInstallScripts: detectInstallScripts(extracted.files) || input.meta.hasInstallScripts,
    signature,
    provenance: input.hasProvenance ? "present" : "absent",
  };
```
> This replaces the existing `const meta = {...}` block (which set `integrity` and sizes). Remove the now-duplicated `integrity` const if you introduce a new one — keep exactly one `integrity` binding.

**`packages/proxy/src/upstream.ts`:**
- Add import at top: `import type { RegistrySignature } from "@sentinel/core";`
- `UpstreamVersion`: replace `signatureStatus: "signed" | "unsigned" | "unknown";` with:
```ts
  signatures: RegistrySignature[] | null;
  hasProvenance: boolean;
```
- `VersionManifest.dist`: change `signatures?: unknown[]` to `signatures?: { keyid: string; sig: string }[]`.
- `normalizeVersion`: replace the `signed`/`provenance`/`signatureStatus` lines with:
```ts
  signatures: Array.isArray(m.dist?.signatures) && m.dist.signatures.length > 0 ? m.dist.signatures : null,
  hasProvenance: Boolean(m.dist?.attestations),
```
- `RegistryDoc` (the fixture-file shape): in the per-version object, replace `signatureStatus: "signed" | "unsigned" | "unknown";` with:
```ts
  signatures?: { keyid: string; sig: string }[] | null;
  attestations?: boolean;
```
- `LocalFixtureUpstream.getPackument`: in the `versions[v] = {...}` object replace `signatureStatus: m.signatureStatus,` with `signatures: m.signatures ?? null, hasProvenance: Boolean(m.attestations),`. In the `docVersions[v].dist` object add `signatures: m.signatures ?? undefined, attestations: m.attestations ? {} : undefined` so the doc round-trips the presence.

**`packages/proxy/src/server.ts`:**
- Extend the `@sentinel/core` import with `NPM_SIGNING_KEYS, type NpmSigningKey`.
- `ServerOptions`: add `signingKeys?: NpmSigningKey[];`
- In `createServer`, after other opts: `const signingKeys = opts.signingKeys ?? NPM_SIGNING_KEYS;`
- In `auditVersion`, pass the raw material + keys into `runAudit`:
```ts
    const audit = await runAudit({ meta, tarball, baselineTarball, signatures: vmeta.signatures, hasProvenance: vmeta.hasProvenance, signingKeys });
```
- The **private** branch (`isClaimed`) scores a cached `Audit` whose `meta` already carries `signature`/`provenance` (set at publish). No change needed here beyond the publish path below.
- **Publish path** (`app.put`-style publish handler calling `runAudit` ~line 251): private packages are not npm-signed, so pass `signatures: null, hasProvenance: false` (the resulting `meta.signature` will be `"unsigned"`). No other change.

**`packages/cli/src/index.ts`** — in the `scan` action meta, replace `hasInstallScripts: false, signatureStatus: "unknown",` with `hasInstallScripts: false,` (a local `.tgz` has no registry metadata; `runAudit` will set `signature: "unsigned"`, `provenance: "absent"` since `scan`/`auditTarball` pass no signatures).

**`packages/cli/src/format.ts`** — the current `formatReport` reads `m.signatureStatus`. To keep it compiling now (full rework in Task 6), replace the three `signatureStatus` lines with a minimal:
```ts
  L.push(`  signature  ${m.signature}`);
  L.push(`  provenance ${m.provenance}`);
```

**Test metas** — in `packages/core/test/audit.test.ts`, `capabilities.test.ts`, `score.test.ts`, and `packages/proxy/test/private-serve.test.ts`, replace every `signatureStatus: "unknown" as const,` (or similar) in hand-built `PackageMeta`/meta literals with:
```ts
  signature: "verified" as const, provenance: "present" as const,
```
> Use `verified`/`present` (not `unknown`) so that once the Task 4 rule exists these unit inputs emit NO provenance finding and their assertions stay stable.

**`packages/proxy/public/index.html`** — leave for Task 6 (dashboard is not type-checked; update it there).

- [ ] **Step 4: Run tests + build to verify green**

Run: `npm run build && npm test`
Expected: build clean; full suite green at the baseline count + 2 new tests (Task 1's file + this task's new test). Existing verdicts unchanged (no rule reads the new fields yet). If any existing test breaks, it is a missed `signatureStatus` consumer — fix it, do not weaken the test.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(core+proxy+cli): un-flatten signatureStatus into verified signature + provenance"
```

---

### Task 3: Fixture signing + fixture data

**Files:**
- Modify: `scripts/make-fixtures.ts` (generate/persist test key, sign, write `signatures`/`attestations` + `fixtures/signing-keys.json`)
- Modify: `fixtures/index.json` (per-version intent flags)
- Create: fixture dirs `fixtures/benign/sig-tampered/1.0.0/package/`, `sig-unsigned/1.0.0/package/`, `sig-unknown/1.0.0/package/`, `prov-absent/1.0.0/package/` (each a trivial benign package)
- Modify: `.gitignore` (ignore generated signing artifacts)
- Test: `packages/proxy/test/signature-verify.test.ts`

**Interfaces:**
- Produces: `fixtures/signing-keys.json` (a `NpmSigningKey[]`), and `registry.json` version entries carrying `signatures`/`attestations`.
- Consumes: `verifyRegistrySignature`, `NpmSigningKey` (Task 1); `LocalFixtureUpstream` carrying `signatures`/`hasProvenance` (Task 2).

- [ ] **Step 1: Write the failing test**

Create `packages/proxy/test/signature-verify.test.ts`:

```ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, describe, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { DEFAULT_POLICY, type NpmSigningKey } from "@sentinel/core";
import { createServer } from "../src/server.js";
import { AuditStore } from "../src/store.js";
import { LocalFixtureUpstream } from "../src/upstream.js";
import { ApprovalStore } from "../src/approvals.js";
import { PrivatePackageStore } from "../src/private-store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO_ROOT, "fixtures");
const KEYS_FILE = join(FIXTURES, "signing-keys.json");

function ensureFixtures(): void {
  if (existsSync(join(FIXTURES, "registry.json")) && existsSync(join(FIXTURES, ".tarballs")) && existsSync(KEYS_FILE)) return;
  execFileSync("npx", ["tsx", join(REPO_ROOT, "scripts", "make-fixtures.ts")], { cwd: REPO_ROOT, stdio: "ignore" });
}

async function sig(base: string, pkg: string, version: string): Promise<string> {
  const r = await fetch(`${base}/-/audit/${pkg}/${version}`);
  const report = (await r.json()) as { meta: { signature: string; provenance: string } };
  return `${report.meta.signature}/${report.meta.provenance}`;
}

describe("registry signature verification (local fixtures, test keys)", () => {
  let server: Server; let base: string;
  before(async () => {
    ensureFixtures();
    const signingKeys = JSON.parse(readFileSync(KEYS_FILE, "utf8")) as NpmSigningKey[];
    const app = createServer({
      upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(),
      approvals: new ApprovalStore(), enterprisePolicy: DEFAULT_POLICY,
      privateStore: new PrivatePackageStore(), signingKeys,
    });
    await new Promise<void>((res) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; res(); }); });
  });
  after(() => server?.close());

  test("a validly-signed fixture verifies with provenance present", async () => {
    assert.equal(await sig(base, "leftpad-lite", "1.0.0"), "verified/present");
  });
  test("a tampered signature is invalid", async () => {
    assert.equal((await sig(base, "sig-tampered", "1.0.0")).split("/")[0], "invalid");
  });
  test("an unsigned fixture is unsigned", async () => {
    assert.equal((await sig(base, "sig-unsigned", "1.0.0")).split("/")[0], "unsigned");
  });
  test("an unknown-keyid signature is unknown", async () => {
    assert.equal((await sig(base, "sig-unknown", "1.0.0")).split("/")[0], "unknown");
  });
  test("a fixture without attestations has provenance absent", async () => {
    assert.equal((await sig(base, "prov-absent", "1.0.0")).split("/")[1], "absent");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/proxy/test/signature-verify.test.ts`
Expected: FAIL — `signing-keys.json` doesn't exist / fixtures aren't signed / `sig-*` packages unknown.

- [ ] **Step 3: Write minimal implementation**

**New fixture packages** — for each of `sig-tampered`, `sig-unsigned`, `sig-unknown`, `prov-absent`, create `fixtures/benign/<name>/1.0.0/package/package.json`:
```json
{ "name": "<name>", "version": "1.0.0", "description": "SYNTHETIC FIXTURE — signature/provenance test", "license": "MIT", "main": "index.js" }
```
and `fixtures/benign/<name>/1.0.0/package/index.js`:
```js
// SYNTHETIC FIXTURE — inert. Exercises signature/provenance verification only.
module.exports = 1;
```

**`fixtures/index.json`** — replace each version's `{ "signatureStatus": "..." }` with intent flags. Set every EXISTING version to `{ "signature": "valid", "provenance": true }` (so they verify + carry provenance → no findings once the rule lands). Add the new packages:
```json
"sig-tampered":  { "class": "benign", "versions": { "1.0.0": { "signature": "tampered",    "provenance": true  } } },
"sig-unsigned":  { "class": "benign", "versions": { "1.0.0": { "signature": "none",        "provenance": true  } } },
"sig-unknown":   { "class": "benign", "versions": { "1.0.0": { "signature": "unknown-key", "provenance": true  } } },
"prov-absent":   { "class": "benign", "versions": { "1.0.0": { "signature": "valid",       "provenance": false } } }
```

**`scripts/make-fixtures.ts`:**
- Update `IndexFile` version shape: `{ signature: "valid" | "tampered" | "unknown-key" | "none"; provenance: boolean }`.
- Update `RegistryVersion`: drop `signatureStatus`; add `signatures?: { keyid: string; sig: string }[] | null; attestations?: boolean`.
- Add imports: `import { generateKeyPairSync, sign, createHash } from "node:crypto";` and `existsSync` from `node:fs`.
- Before the packages loop, load-or-generate the synthetic key and write the public keyset:
```ts
const SIGNING_DIR = join(FIX, "signing");
const KEY_FILE = join(SIGNING_DIR, "test-key.json");
mkdirSync(SIGNING_DIR, { recursive: true });
let priv: string, keyid: string;
if (existsSync(KEY_FILE)) {
  ({ priv, keyid } = JSON.parse(readFileSync(KEY_FILE, "utf8")));
} else {
  const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
  priv = kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const spkiDer = kp.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  keyid = "SHA256:" + createHash("sha256").update(spkiDer).digest("base64");
  writeFileSync(KEY_FILE, JSON.stringify({ priv, keyid, spkiPem: kp.publicKey.export({ type: "spki", format: "pem" }).toString() }, null, 2));
}
const keyMeta = JSON.parse(readFileSync(KEY_FILE, "utf8")) as { priv: string; keyid: string; spkiPem: string };
writeFileSync(join(FIX, "signing-keys.json"), JSON.stringify([{ keyid: keyMeta.keyid, spkiPem: keyMeta.spkiPem, expires: null }], null, 2) + "\n");
```
- After computing `integrity` for a version, build the `signatures`/`attestations` per intent:
```ts
import { createPrivateKey } from "node:crypto"; // add to imports
// ...
const payload = Buffer.from(`${name}@${version}:${integrity}`);
let signatures: { keyid: string; sig: string }[] | null = null;
if (vmeta.signature === "valid") {
  signatures = [{ keyid: keyMeta.keyid, sig: sign("sha256", payload, createPrivateKey(keyMeta.priv)).toString("base64") }];
} else if (vmeta.signature === "tampered") {
  const bad = Buffer.from(`${name}@${version}:sha512-TAMPERED`);
  signatures = [{ keyid: keyMeta.keyid, sig: sign("sha256", bad, createPrivateKey(keyMeta.priv)).toString("base64") }];
} else if (vmeta.signature === "unknown-key") {
  signatures = [{ keyid: "SHA256:unknown-test-key", sig: sign("sha256", payload, createPrivateKey(keyMeta.priv)).toString("base64") }];
} // "none" -> null
entry.versions[version] = {
  version, author, license: pkgJson.license ?? null, hasInstallScripts,
  dist: { tarballFile: tarballName, integrity, unpackedSize, fileCount },
  signatures, attestations: vmeta.provenance,
};
```
> Remove the old `signatureStatus: vmeta.signatureStatus` line.

**`.gitignore`** — add:
```
fixtures/signing/
fixtures/signing-keys.json
```

- [ ] **Step 4: Regenerate fixtures + run test**

Run: `npm run fixtures && node --import tsx --test packages/proxy/test/signature-verify.test.ts`
Expected: PASS (5 tests). Then `npm test` — full suite still green (no rule yet; new fixtures are benign and un-scored on signature). Commit the regenerated `fixtures/registry.json` (its `sig` bytes churn per rebuild — ECDSA nonce — which is cosmetic and expected; `pretest`/`ensureFixtures` always regenerate it consistently).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "fixtures: sign fixtures with a synthetic key + sig/prov intent fixtures"
```

---

### Task 4: Provenance/signature detection rule

**Files:**
- Modify: `packages/core/src/types.ts` (add `"provenance"` to `Category`)
- Create: `packages/core/src/rules/provenance.ts`
- Modify: `packages/core/src/rules/index.ts` (register)
- Test: `packages/core/test/provenance-rule.test.ts`

**Interfaces:**
- Consumes: `AuditInput` with `meta.signature` / `meta.provenance` (Task 2); `mkFinding` from `rules/util.ts`.
- Produces: `provenanceRule: Rule` (id `"provenance"`, category `"provenance"`).

- [ ] **Step 1: Write the failing test**

Create `packages/core/test/provenance-rule.test.ts`:

```ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { provenanceRule } from "../src/rules/provenance.js";
import type { AuditInput, PackageMeta } from "../src/types.js";

function input(signature: PackageMeta["signature"], provenance: PackageMeta["provenance"]): AuditInput {
  return {
    meta: { name: "p", version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, signature, provenance, integrity: "sha512-x", unpackedSize: 1, fileCount: 1 },
    files: [], mode: "full",
  };
}

describe("provenanceRule", () => {
  test("invalid signature is critical", () => {
    const f = provenanceRule.run(input("invalid", "present"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "critical");
  });
  test("unsigned is low", () => {
    assert.equal(provenanceRule.run(input("unsigned", "present"))[0]!.severity, "low");
  });
  test("unknown is info", () => {
    assert.equal(provenanceRule.run(input("unknown", "present"))[0]!.severity, "info");
  });
  test("absent provenance is info", () => {
    const f = provenanceRule.run(input("verified", "absent"));
    assert.equal(f.length, 1);
    assert.equal(f[0]!.severity, "info");
  });
  test("verified + present emits nothing", () => {
    assert.deepEqual(provenanceRule.run(input("verified", "present")), []);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/core/test/provenance-rule.test.ts`
Expected: FAIL — cannot find module `../src/rules/provenance.js`.

- [ ] **Step 3: Write minimal implementation**

In `packages/core/src/types.ts`, add `"provenance"` to the `Category` union:
```ts
export type Category =
  | "obfuscation"
  | "network"
  | "secret-exfil"
  | "install-script"
  | "metadata"
  | "provenance";
```

Create `packages/core/src/rules/provenance.ts`:
```ts
import type { AuditInput, Finding, Rule } from "../types.js";
import { mkFinding } from "./util.js";

/**
 * Surfaces the verified registry-signature and provenance status as findings.
 * The verification itself runs in the audit-assembly path (offline); this rule
 * only reads the already-verified `meta` and never sets the score directly —
 * severity weights + the policy gate decide impact.
 */
export const provenanceRule: Rule = {
  id: "provenance",
  category: "provenance",
  run(input: AuditInput): Finding[] {
    const { signature, provenance } = input.meta;
    const out: Finding[] = [];
    const add = (severity: Finding["severity"], message: string) =>
      out.push(mkFinding({ ruleId: "provenance", category: "provenance", severity, message, evidence: [], files: input.files }));

    if (signature === "invalid") add("critical", "registry signature failed verification — possible tampering");
    else if (signature === "unsigned") add("low", "package has no registry signature");
    else if (signature === "unknown") add("info", "registry signature present but no trusted key to verify it");

    if (provenance === "absent") add("info", "no build provenance attestation");
    return out;
  },
};
```

In `packages/core/src/rules/index.ts`, import + register:
```ts
import { provenanceRule } from "./provenance.js";
// ... in RULES array (append):
  provenanceRule,
// ... in the re-export block:
  provenanceRule,
```

- [ ] **Step 4: Run tests + full suite**

Run: `node --import tsx --test packages/core/test/provenance-rule.test.ts && npm test`
Expected: rule tests PASS (5). Full suite green: existing benign fixtures are `verified`/`present` (Task 3) → no new findings; `color-stream` still blocks on its content rules; the `sig-tampered` fixture now scores a critical finding (but nothing asserts its verdict yet — that's Task 5). If a fixture-scoring test breaks, confirm the fixture is `verified`/`present` in `index.json` (not that the assertion is wrong).

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/rules/provenance.ts packages/core/src/rules/index.ts packages/core/test/provenance-rule.test.ts
git commit -m "feat(core): provenance rule — surfaces signature/provenance status (invalid = critical)"
```

---

### Task 5: Policy gate — requireSignature / requireProvenance

**Files:**
- Modify: `packages/core/src/policy.ts` (`EnterprisePolicy` fields + `parsePolicy` validation)
- Modify: `packages/core/src/score.ts` (gate)
- Test: `packages/core/test/score.test.ts` (gate unit tests) + `packages/proxy/test/signature-verify.test.ts` (policy integration)

**Interfaces:**
- Consumes: `matchPackage` (existing), `meta.signature`/`meta.provenance`.
- Produces: `EnterprisePolicy.requireSignature?: string[]`, `EnterprisePolicy.requireProvenance?: string[]` (optional, default `[]`).

- [ ] **Step 1: Write the failing test**

Add to `packages/core/test/score.test.ts`:
```ts
import { score } from "../src/score.js";
import { DEFAULT_POLICY } from "../src/policy.js";
// build a minimal Audit with a given signature/provenance:
function auditWith(signature: string, provenance: string, name = "acme-lib") {
  return {
    schema: 3 as const, meta: { name, version: "1.0.0", author: null, maintainers: [], license: null, hasInstallScripts: false, signature, provenance, integrity: "sha512-x", unpackedSize: 1, fileCount: 1 },
    findings: [], capabilities: [], capabilityDelta: null,
    engine: { version: "0.1.0", rules: [], mode: "full" as const }, auditedAt: "t", durationMs: 0,
  } as Parameters<typeof score>[0];
}

describe("requireSignature / requireProvenance policy gate", () => {
  test("requireSignature blocks a non-verified package", () => {
    const p = { ...DEFAULT_POLICY, requireSignature: ["acme-*"] };
    assert.equal(score(auditWith("unsigned", "present"), p).verdict, "block");
    assert.equal(score(auditWith("verified", "present"), p).verdict, "allow");
  });
  test("requireProvenance blocks a package without provenance", () => {
    const p = { ...DEFAULT_POLICY, requireProvenance: ["acme-*"] };
    assert.equal(score(auditWith("verified", "absent"), p).verdict, "block");
    assert.equal(score(auditWith("verified", "present"), p).verdict, "allow");
  });
  test("no requirement -> not gated on signature/provenance", () => {
    assert.equal(score(auditWith("unsigned", "absent"), DEFAULT_POLICY).verdict, "allow");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --import tsx --test packages/core/test/score.test.ts`
Expected: FAIL — `requireSignature`/`requireProvenance` not honored (verdict `allow`/`warn`, not `block`).

- [ ] **Step 3: Write minimal implementation**

**`packages/core/src/policy.ts`** — in `EnterprisePolicy`, after `privateNamespaces`:
```ts
  /** Package patterns that MUST have a verified registry signature (ADR-0021). */
  requireSignature?: string[];
  /** Package patterns that MUST carry a provenance attestation (ADR-0021). */
  requireProvenance?: string[];
```
In `parsePolicy`, after the `treeGate` validation:
```ts
  for (const field of ["requireSignature", "requireProvenance"] as const) {
    const v = (p as Record<string, unknown>)[field];
    if (v !== undefined && (!Array.isArray(v) || !v.every((x) => typeof x === "string"))) {
      throw new Error(`invalid policy: ${field} must be an array of strings`);
    }
  }
```
In the `parsePolicy` return object, after the `treeGate` spread:
```ts
    ...((p as { requireSignature?: string[] }).requireSignature !== undefined ? { requireSignature: (p as { requireSignature: string[] }).requireSignature } : {}),
    ...((p as { requireProvenance?: string[] }).requireProvenance !== undefined ? { requireProvenance: (p as { requireProvenance: string[] }).requireProvenance } : {}),
```

**`packages/core/src/score.ts`** — after the `denied` line, add:
```ts
  const reqSig = (policy.requireSignature ?? []).some((p) => matchPackage(p, audit.meta.name)) && audit.meta.signature !== "verified";
  const reqProv = (policy.requireProvenance ?? []).some((p) => matchPackage(p, audit.meta.name)) && audit.meta.provenance !== "present";
```
Change the verdict line:
```ts
  if (denied || hardBlock || reqSig || reqProv) verdict = "block";
```

- [ ] **Step 4: Run tests + full suite**

Run: `node --import tsx --test packages/core/test/score.test.ts && npm test`
Expected: gate tests PASS; full suite green (default policy has no `requireSignature`/`requireProvenance`, so no existing verdict changes).

- [ ] **Step 5: Add a policy integration test + commit**

Add to `packages/proxy/test/signature-verify.test.ts` a test that a proxy under a policy with `requireSignature: ["sig-unsigned"]` blocks `sig-unsigned` — construct a second server in the test with `enterprisePolicy: { ...DEFAULT_POLICY, requireSignature: ["sig-unsigned"], requireProvenance: ["prov-absent"] }` and `policy: "block"`, then assert `GET /sig-unsigned/-/sig-unsigned-1.0.0.tgz` returns 403 (mirror the block-policy request pattern in `proxy.test.ts`). Run the file, then:
```bash
git add packages/core/src/policy.ts packages/core/src/score.ts packages/core/test/score.test.ts packages/proxy/test/signature-verify.test.ts
git commit -m "feat(core): requireSignature/requireProvenance policy gate (ADR-0021)"
```

---

### Task 6: Surfacing + docs

**Files:**
- Modify: `packages/cli/src/format.ts` (`formatReport` signature/provenance lines with color)
- Modify: `packages/proxy/public/index.html` (dashboard)
- Create: `docs/adr/0021-signature-provenance-verification.md`
- Modify: `ARCHITECTURE.md` (§3.9 + TOC line)
- Modify: `CLAUDE.md` (phase paragraph + test count)
- Modify: `README.md` (mention signature/provenance)
- Test: none new (docs/display); the field values are already asserted in Tasks 3/5.

- [ ] **Step 1: Update `formatReport` display**

In `packages/cli/src/format.ts`, replace the minimal signature/provenance lines added in Task 2 with colored output (reuse existing `C`/`c`):
```ts
  const sig = m.signature === "verified" ? c(C.green, "verified")
    : m.signature === "invalid" ? c(C.red, "invalid")
    : m.signature === "unsigned" ? c(C.yellow, "unsigned") : c(C.gray, "unknown");
  L.push(`  signature  ${sig}`);
  L.push(`  provenance ${m.provenance === "present" ? c(C.green, "present") : c(C.gray, "absent")}`);
```

- [ ] **Step 2: Update the dashboard**

In `packages/proxy/public/index.html`, replace the `signatureStatus` span (line ~103) with:
```html
      sig: <span class="sig-${m.signature}">${m.signature}</span> · prov: ${m.provenance}<br/>
```

- [ ] **Step 3: Verify display compiles/runs**

Run: `npm run build && node --import tsx --test packages/cli/test/cli.test.ts`
Expected: build clean; CLI tests green (formatReport still renders).

- [ ] **Step 4: Write ADR-0021**

Create `docs/adr/0021-signature-provenance-verification.md`, mirroring the `**Status:**`/`**Date:**` bold-line format of `docs/adr/0020-whole-tree-lockfile-audit.md`. Content must cover:
```markdown
# ADR-0021: Signature & provenance verification

## Status
Accepted (Phase 8).

## Context
`normalizeVersion` flattened `signed || provenance → "signed"` and discarded the detail; no
rule or policy acted on it, despite the threat model promising to "surface signature/provenance
status."

## Decision
- **Un-flatten** `PackageMeta.signatureStatus` into `signature: verified|invalid|unsigned|unknown`
  + `provenance: present|absent`.
- **Verify the npm registry signature offline** — ECDSA P-256, SHA-256, **DER** encoding (Node's
  default; the common IEEE-P1363 assumption is wrong — confirmed live against `/-/npm/v1/keys`,
  where `left-pad@1.3.0` verified under DER and failed under ieee-p1363). Payload
  `${name}@${version}:${integrity}`. Keys are matched by `keyid` against a configured set
  (`NPM_SIGNING_KEYS`, both current npm keys bundled), a **static input never fetched at audit
  time** (invariant #3). `invalid` ⇒ critical ⇒ hard-block.
- **Rule vs gate split:** a pure `provenance` rule surfaces status as findings (it cannot see
  policy); the conditional gate lives in `score.ts` beside `deny`, driven by optional
  `requireSignature`/`requireProvenance` pattern lists.
- **Provenance gated on presence** this phase.

## Consequences
- Real MITM/compromised-mirror defense for the proxy; policy can require provenance for a namespace.
- Key rotation/expiry: keys are matched by `keyid`; expiry is surfaced, not enforced (a package
  signed under a since-rotated key stays `verified`).
- Deferred: full Sigstore/Rekor attestation-bundle verification (async-enrich follow-up);
  expiry-as-invalid; automatic key refresh; verifying provenance contents (repo/builder identity).

## Rejected
- IEEE-P1363 signature encoding (empirically wrong for npm).
- Verifying inline with a network fetch (violates invariant #3).
- Making verification a rule (rules are pure and can't see policy or configured keys).
```

- [ ] **Step 5: Update ARCHITECTURE / CLAUDE / README + commit**

`ARCHITECTURE.md`: add `### 3.9 Signature & provenance verification (Phase 8, ADR-0021)` after §3.8, with a paragraph describing offline registry-sig verification (keyid-matched configured keys, DER, invariant #3), the `signature`/`provenance` fields, the rule, and the `requireSignature`/`requireProvenance` gate.

`CLAUDE.md`: add a Phase 8 paragraph to "What this is" (after Phase 7); update the `npm test` count from an actual `npm test` run (record the observed darwin totals — do not guess).

`README.md`: add a short line noting `sentinel` now verifies the npm registry signature offline and can require signature/provenance via policy.

Run: `npm test` (confirm green + source the count), then:
```bash
git add packages/cli/src/format.ts packages/proxy/public/index.html docs/adr/0021-signature-provenance-verification.md ARCHITECTURE.md CLAUDE.md README.md
git commit -m "docs(phase8): ADR-0021; ARCHITECTURE §3.9; CLAUDE phase+count; README; colored signature/provenance output"
```

---

## Self-Review

**Spec coverage:**
- §1 offline registry-sig verify + provenance presence → Task 1 (verify fn) + Task 2 (wire) + Task 4 (surface) + Task 5 (gate).
- §2 un-flatten `signature`+`provenance` + carry raw material → Task 2.
- §3 `signature.ts`, `NPM_SIGNING_KEYS`, keyid match, runAudit wiring, invariant #3 → Tasks 1–2.
- §4 provenance rule severities (invalid=critical … verified+present=none) + `"provenance"` category → Task 4.
- §5 `requireSignature`/`requireProvenance` optional pattern lists + score gate + parse validation → Task 5.
- §6 determinism/offline → Task 1 (pure fn) verified by unit tests.
- §7 hermetic fixtures (test key, verified/invalid/unsigned/unknown, provenance present/absent, policy blocks) → Task 3 (+ Task 5 integration).
- §8 non-goals → not built; recorded in ADR (Task 6).
- §6 surfacing (format/dashboard) → Task 6. §9 ADR-0021 → Task 6.

**Placeholder scan:** No TBD/TODO. The only runtime-sourced value is the test count in Task 6 Step 5 (read from `npm test`, not guessed). Task 2's new test references a fixture-tarball load "helper if present" — instruction gives the exact `readFileSync` fallback.

**Type consistency:** `SignatureVerdict` defined once in `types.ts`, re-exported by `signature.ts`; used identically in `PackageMeta`, `verifyRegistrySignature`, the rule, and the gate. `RegistrySignature`/`NpmSigningKey` from `signature.ts` used in `audit.ts`, `upstream.ts`, `server.ts`, and the fixture keyset. `signature`/`provenance` field names consistent across core → proxy → cli → fixtures → tests. Rule id/category `"provenance"` consistent (Task 4 registers it; Task 5 gate is independent of the rule). Policy fields `requireSignature`/`requireProvenance` consistent between `policy.ts`, `score.ts`, and the tests.

# Phase 27 — remaining security-review hardening (#10, #11, #12) — design

**Date:** 2026-07-10
**Status:** Approved
**Closes:** [#10](https://github.com/git-agentic/pkg-registry/issues/10) (pin Action deps to SHAs),
[#11](https://github.com/git-agentic/pkg-registry/issues/11) (static-scan blind spot),
[#12](https://github.com/git-agentic/pkg-registry/issues/12) (non-SLSA attestation labeled `verified`)

Three small, independent P2/P3 fixes from the external review, delivered as **one PR**
(branch `review-hardening`). One ADR (0041) covers the two behavioral changes (#11, #12);
#10 is CI hygiene and needs none.

---

## #10 — Pin GitHub Action dependencies to commit SHAs

### Problem

`action.yml` and the workflows reference third-party actions by mutable major-version
tags (`@v4`, `@v3`), which can be repointed after review. For a project whose thesis is
supply-chain pinning, unpinned actions are a dogfooding-credibility gap.

### Design

Pin every third-party `uses:` to a full 40-char commit SHA with a trailing `# vX.Y.Z`
comment. Sites:
- `action.yml`: `actions/setup-node@v4`, `actions/upload-artifact@v4`, `actions/github-script@v7`
- `.github/workflows/ci.yml`: `actions/checkout@v4`, `actions/setup-node@v4`
- `.github/workflows/codeql.yml`: `actions/checkout@v4`, `github/codeql-action/init@v3`, `github/codeql-action/analyze@v3`
- `.github/workflows/sentinel-example.yml`: `actions/checkout@v4`

`uses: ./` (the local composite action in `sentinel-example.yml`) is NOT pinned — it's a
local path, not a third-party ref.

Resolve each tag → SHA at authoring time via `gh api repos/<owner>/<repo>/git/refs/tags/<tag>`
(dereference annotated tags to the commit). Pin to the SHA the current tag points to, so
behavior is unchanged; only mutability is removed.

Add a short **"Updating pinned actions"** note to `CONTRIBUTING.md`: bump the SHA + the
`# vX.Y.Z` comment together when updating; mention Dependabot-for-actions raises
SHA-pinned bump PRs as the maintenance path.

### Testing

CI itself is the test: the `ci`, `codeql`, and `Sentinel` workflows must run green with the
SHAs (proves the pins resolve). No unit tests.

---

## #11 — Surface unscanned executable-looking content

### Problem

`extractTarball` counts but does not scan files over 2 MB (`MAX_FILE_BYTES`) or with a
non-text extension (`TEXT_EXT`). Malicious behavior in a large generated `.js`, or in a
native/WASM payload, evades every rule **silently** — no signal that a blind spot was hit.

### Design

**Track the blind spot in `extractTarball`.** Add a bounded `unscanned` list to
`ExtractResult`:

```ts
export interface UnscannedEntry { path: string; size: number; kind: "large-code" | "native"; }
// ExtractResult gains: unscanned: UnscannedEntry[];
```

While extracting, when a File entry is counted but not retained for scanning, classify it:
- **`large-code`**: extension in the code set `.js/.mjs/.cjs/.ts/.mts/.cts/.jsx/.tsx` AND
  size > `MAX_FILE_BYTES` (a large code file that escaped the text scan).
- **`native`**: extension in `.node/.wasm/.so/.dll/.dylib/.exe` (binary/native, never scanned).

Push `{ path, size, kind }` for matches, **capped at 100 entries** (a `truncated`-style
guard against a pathological many-binary tarball inflating memory; beyond the cap, stop
appending — the finding still fires). Non-executable skipped files (`.png`, `.md` over
2 MB, etc.) are NOT tracked — only executable-looking content.

**Synthesize the finding in `runAudit`** (same mechanism as `resource-abuse` /
`integrity-mismatch` — it needs extract metadata, not `AuditInput`, so it is not a `Rule`):
- If `extracted.unscanned` is non-empty → a **LOW** `unscanned-content` finding, category
  `metadata`, message summarizing count + total bytes + kinds (e.g. "3 executable-looking
  files (12.4 MB) were not scanned: 2 large-code, 1 native").
- **Escalate to MEDIUM** when at least one `native` entry is present AND the package runs
  install scripts (`detectInstallScripts(extracted.files)`, already used in `audit.ts`) —
  native code paired with install-time execution is the sharper signal. Message notes the
  native + install-script combination.

Only the **current** tarball's `unscanned` drives the finding (diff mode: the baseline's is
ignored, mirroring `resource-abuse`). Category weighting is by severity, so LOW/MEDIUM
contribute via `severityWeight` and never hard-block on their own (invariant #1: the
finding is deterministic — depends only on the file list + sizes + install-script flag, no
wall-clock).

### Testing

- `extractTarball` unit: a tarball with a >2 MB `.js` → `unscanned` has one `large-code`;
  a `.node` file → one `native`; a benign small package → empty `unscanned`; the 100-entry
  cap holds.
- `runAudit`/`auditTarball`: >2 MB `.js` → a LOW `unscanned-content` finding; a `.node` +
  a `postinstall` script → a MEDIUM finding; benign → no such finding; determinism.
- Benign fixtures still score unchanged (they have no large-code/native content), the
  malicious fixture still blocks.

---

## #12 — Require the SLSA v1 predicate for `verified`

### Problem

`verifyProvenance` returns `status: "verified"` whenever the bundles verify cryptographically
and bind to the served bytes — it extracts identity only from an SLSA v1 bundle but does not
*require* one. So a cryptographically-valid attestation with only a non-SLSA predicate reads
`verified` with `identity: null`. The `requireProvenance` gate demands identity so it isn't
bypassable today, but the **status label is misleading**.

### Design

In `verifyProvenance`'s bundle loop, track whether any bundle carried the SLSA v1 predicate:

```ts
let sawSlsa = false;
for (const a of list) {
  // … verify + checkSubjectBinding (unchanged; a bind error still returns "invalid") …
  if (stmt.predicateType === SLSA_V1) { identity = extractIdentity(result, stmt); sawSlsa = true; }
}
if (!sawSlsa) {
  return { status: "unknown", identity: null,
    reason: "attestation present but no recognized SLSA v1 provenance predicate", rootStale };
}
return { status: "verified", identity, reason: null, rootStale };
```

- Legit npm packages carry an SLSA v1 provenance bundle alongside the publish attestation,
  so they still reach `verified` with identity — unchanged.
- A bundle set that verifies but is *only* non-SLSA → `unknown` (not `verified`). The
  `provenance` rule already emits a LOW finding for `unknown`, and `requireProvenance`
  already fails on non-`verified` — the gate tightens correctly with **no new status value**.
- A crypto/verification failure over a *present* bundle still maps to `invalid` (the outer
  `catch` is unchanged), so a crash-bundle can't fail open past the gate (ADR-0022 invariant
  preserved).

**Message accuracy fix.** The `provenance` rule's `unknown` message currently reads
"provenance attested but could not be verified (bundle unavailable or no trust material)" —
which would misdescribe the new non-SLSA case. Soften it to cover all `unknown` causes,
e.g. "provenance attested but not established as verified SLSA v1 provenance (unrecognized
predicate, bundle unavailable, or no trust material)".

### Testing

- `verifyProvenance` unit: an SLSA v1 bundle → `verified` with identity (unchanged); a bundle
  that verifies but has only a non-SLSA predicate → `unknown` with the distinct reason,
  `identity: null`; a bind mismatch → still `invalid`; a verification throw over a present
  bundle → still `invalid`.
- The `requireProvenance` policy gate rejects the non-SLSA `unknown` case.
- Update any existing provenance test that pinned the old non-SLSA-→-`verified` behavior to
  the corrected expectation.

---

## Delivery & docs

- One PR (`review-hardening`) closing #10, #11, #12.
- **ADR-0041** covers the two behavioral changes: the scan-coverage `unscanned-content`
  finding (#11) and the SLSA-predicate requirement for `verified` (#12). #12 extends
  ADR-0022's provenance-verification lineage (does not supersede it). #10 is CI hygiene,
  no ADR.
- CLAUDE.md (Phase 27 paragraph + `unscanned-content` in the rule/finding notes),
  ARCHITECTURE.md (scan-coverage + provenance sections), README.md if any env/behavior
  surface changes (none expected — no new env vars).

## Definition of done

`npm run build` clean; `npm test` green with new tests; ADR-0041 + doc updates; malicious
fixture still blocks; CI green with SHA-pinned actions. One PR closing all three issues.

## Out of scope

- Bounded scanning of large files (scan first N KB) — considered for #11, not chosen; the
  low+escalate finding surfaces the blind spot without changing scan semantics or the
  false-positive profile.
- A new `ProvenanceStatus` value for #12 — reusing `unknown` achieves the correct gate and
  a non-misleading label with no new surface.
- Auto-updating pinned action SHAs — documented as a Dependabot maintenance path, not
  automated here.

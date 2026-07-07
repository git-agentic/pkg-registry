# Phase 14 — Ecosystem Breadth + SBOM (yarn/pnpm lockfiles, CycloneDX, integrity cross-check, --fail-on-error)

**Date:** 2026-07-07
**Status:** Approved design, pre-implementation
**Extends:** ADR-0020 (whole-tree lockfile audit — this closes its own deferred
list), ADR-0009 (integrity-hash cache key — the cross-check reuses the recomputed
served integrity from Phase 9), ADR-0002 (deterministic scoring — untouched; this is
tree/CLI tooling). Supersedes nothing.

## Problem

Sentinel's whole-tree CI gate (Phase 7, ADR-0020) understands only npm's
`package-lock.json`. yarn and pnpm dominate a large share of real projects, so the
gate is blind to them. It also emits no SBOM — a named compliance artifact (US EO
14028, SLSA) — performs no lockfile-integrity-vs-served cross-check, and deliberately
fails open on `error` rows with no way to opt into failing closed. ADR-0020 listed all
four as deferred. Phase 14 delivers them, turning a deep engine into one deployable in
real polyglot CI.

## Decisions (brainstorm outcomes)

1. **Full ecosystem coverage (npm + yarn + pnpm) with a YAML dependency.** pnpm-lock.yaml
   and yarn-berry locks are genuine YAML; hand-rolling a YAML parser is a
   correctness/security risk. The `yaml` library (2.9.0) is added to `@sentinel/core`
   only. Rejected: npm+yarn-v1-only (leaves pnpm — a third of the ecosystem — unsupported)
   and a regex/line pnpm extractor (brittle; the quiet-gap failure mode a security gate
   must not have).
2. **CycloneDX 1.6 JSON** SBOM (the dominant, EO/SLSA-aligned standard), as a pure
   projection of the existing audit-tree result — no new audit data.
3. **The integrity cross-check reuses Phase 9's recomputed served integrity**
   (`report.meta.integrity`) — the lockfile's claimed SRI is compared to what the
   registry actually serves; a mismatch gates the row.
4. **`--fail-on-error` is opt-in**, flipping ADR-0020's deliberate fail-open only when
   the operator asks — backward compatible.

## Section 1 — Architecture & data flow

Four features extending the Phase 7 gate, mostly in `@sentinel/core` where
`parseLockfile` lives:

- **Multi-format parsing** — keep `parseLockfile` (npm v2/v3). Add `parseYarnLock`
  (yarn v1 text + yarn-berry YAML), `parsePnpmLock` (YAML), and a dispatcher
  `parseAnyLockfile(raw, { filename?, omitDev? }): Coordinate[]` that detects format by
  filename (`package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`) then content sniff.
  All return the same `Coordinate[]` (`{ name, version, integrity? }`). `yaml` is added
  to `@sentinel/core` only.
- **CycloneDX SBOM** — `toCycloneDX(tree: TreeAuditResult, opts: { now: string }): object`
  in core, pure. Emitted via `sentinel audit-tree --sbom <file>`.
- **Integrity cross-check** — the `POST /-/audit-tree` coordinates gain optional
  `integrity`; the route compares it to `report.meta.integrity` and gates a mismatched
  row. The CLI threads each coordinate's SRI through.
- **`--fail-on-error`** — an `aggregateTree` option; the CLI flag sets it.

## Section 2 — Multi-format lockfile parsing

`parseAnyLockfile(raw, { filename?, omitDev? }): Coordinate[]` dispatches by filename,
then content sniff; every parser returns `Coordinate[]`:

- **npm** — existing `parseLockfile` (v2/v3 `packages` map), unchanged.
- **yarn v1** — bespoke text parser. A block's header key
  (`"lodash@^4.17.0", lodash@^4.17.21:`) yields the name (range stripped after the last
  `@`, scope-aware); the indented `version "4.17.21"` yields the resolved version;
  `integrity sha512-…` yields the SRI. yarn v1 locks carry no dev/prod flag, so
  `omitDev` is a documented no-op for this format.
- **yarn-berry (v2+)** — YAML; keys like `"lodash@npm:^4.17.0"` →
  `{ version, resolution, checksum }`. Skip `__metadata`. Berry's `checksum` is a zip
  hash, not SRI, so `integrity` is left absent (the cross-check skips packages without a
  comparable SRI).
- **pnpm-lock.yaml** — YAML; the `packages`/`snapshots` map keyed `/name@version` (v6/v9)
  or `/name/version` (v5), with `resolution.integrity` for the SRI. Handles both key
  shapes; skips `link:`/`file:` entries.

All handle scoped names (`@scope/name`), dedup by `name@version`, sort deterministically,
and throw a clear error on a malformed/unrecognized file (the CLI surfaces it).
`Coordinate.integrity` (already optional) carries the claimed SRI where the format
provides one, feeding Section 3's cross-check.

## Section 3 — SBOM, integrity cross-check, `--fail-on-error`

- **SBOM (CycloneDX 1.6 JSON):** `toCycloneDX(tree, { now })` emits
  `{ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, metadata: { timestamp: now,
  tools: [{ vendor: "Sentinel", name: "sentinel", version: <engine> }] }, components: [...] }`.
  Each package → a `component`: `type: "library"`, `name`, `version`,
  `purl: "pkg:npm/<name>@<version>"` (the `@` of a scoped namespace percent-encoded as
  `%40`), and `properties: [{ name: "sentinel:verdict", value }, { name: "sentinel:score",
  value }, { name: "sentinel:topFinding", value }]`. `now` is injected for deterministic,
  testable output (like Phase 9's `verifyAt`). The CLI adds `sentinel audit-tree --sbom
  <file>` — it writes the BOM in addition to the normal gate summary + exit code.
- **Integrity cross-check:** the `POST /-/audit-tree` body coordinates gain optional
  `integrity`. After auditing each package the route compares the lockfile's claimed SRI
  to `report.meta.integrity` (the recomputed served hash, Phase 9). If both are present
  and differ, the row's `status` becomes `block`, its reason becomes a
  `lockfile-integrity-mismatch` message, and `TreePackageRow.integrityMismatch = true`;
  the aggregate surfaces a count. Packages with no comparable SRI (yarn-berry, or a
  coordinate without integrity) are skipped. Reuses Phase 9's served-bytes recompute —
  no new hashing infrastructure.
- **`--fail-on-error`:** `aggregateTree(rows, treeGate, opts?: { failOnError?: boolean })`
  sets `gated = true` when `opts.failOnError` and any `error` row exists — flipping
  ADR-0020's deliberate fail-open, opt-in. `treeExitCode` already keys off `gated`, so the
  CLI `--fail-on-error` exits non-zero on a tree that failed to fully audit. Off by
  default (backward compatible).

## Section 4 — Testing, fixtures, DoD

*Testing (hermetic, deterministic):*
- **Parser unit tests** — committed sample lockfiles as parser inputs (in the test dir,
  NOT the package `fixtures/`): npm `package-lock.json` v3, `yarn.lock` v1, a yarn-berry
  lock, and `pnpm-lock.yaml` at v6 and v9. Each → asserted `Coordinate[]` (name, version,
  integrity, scoped names); `parseAnyLockfile` proves filename + content-sniff detection;
  a malformed file → a clear thrown error. The samples reference existing fixture package
  names (`leftpad-lite`, `net-fetch-lite`) so the CLI e2e resolves them via
  `LocalFixtureUpstream`.
- **`toCycloneDX` unit test** — a `TreeAuditResult` → assert the CycloneDX shape
  (`bomFormat`/`specVersion`/`components[].purl` + `sentinel:*` properties), injected `now`
  for determinism, scoped-name purl percent-encoding checked.
- **Integrity cross-check** — audit-tree with a coordinate whose claimed integrity differs
  from the served hash → row `block` + `integrityMismatch`; a matching one → no-op
  (in-process proxy + `LocalFixtureUpstream`, whose `registry.json` holds the real
  integrity).
- **`--fail-on-error`** — `aggregateTree` with an `error` row: `failOnError` → gated;
  default → not gated.
- **CLI e2e** — `sentinel audit-tree <yarn.lock>` / `<pnpm-lock.yaml>` resolves + gates;
  `--sbom <file>` writes a valid BOM; `--fail-on-error` flips the exit code. Async
  `execFile` (never `spawnSync` against the in-process proxy — the CLI-child deadlock
  rule).
- **Invariant #1 untouched** — tree/CLI tooling only; the deterministic per-package score
  path is unchanged, so the `scoring is deterministic across runs` test stays green.

*Definition of done:* `npm run build` clean; `npm test` green (new suites); `yaml` added
to `@sentinel/core` only; the malicious fixture still blocked; ADR-0027 recorded;
ARCHITECTURE (the audit-tree/lockfile section + SBOM + the cross-check) + CLAUDE (phase
summary + count) + README (yarn/pnpm support, `--sbom`, `--fail-on-error`, the integrity
cross-check) updated.

## Out of scope (deferred beyond Phase 14)

- bun.lockb / bun.lock support (a binary/text format; add when demand appears).
- SPDX SBOM output (CycloneDX only this phase).
- Full CycloneDX `vulnerabilities` array (Sentinel findings map to `properties`; a formal
  vulnerability projection is a follow-on).
- SBOM signing / attestation (the BOM is an unsigned artifact this phase).
- Transitive-graph edges in the SBOM (`dependencies` / `compositions`) — a flat component
  list this phase.
- Resolving a lockfile's *tree structure* (the parser flattens to a deduped coordinate
  set, matching Phase 7's existing model).

## Invariants preserved

1. **Deterministic score** — the per-package scoring path is untouched; parsing and SBOM
   generation are pure (SBOM's only time input is an injected `now`). The determinism
   test is unaffected.
2. **LLM never scores** — untouched.
3. **Sync gate cheap** — lockfile parsing and SBOM generation happen in the CLI /
   audit-tree batch path, never on the inline tarball gate. The cross-check reuses the
   already-computed served integrity — no extra hashing on the gate path.
4. **Cache key = integrity** — unchanged; the cross-check *reads* the recomputed integrity
   and compares, without altering the cache.
5. **Proxy transparency** — packument passthrough and the tarball path are untouched; the
   audit-tree endpoint gains an optional field only.
6. **Rules fail open / audit never crashes** — a malformed lockfile throws a clear CLI
   error (never a crash mid-audit); an unparseable YAML is caught and surfaced.
7. **Private namespaces authoritative** — unchanged; audit-tree resolves each coordinate
   through the same private/public routing.

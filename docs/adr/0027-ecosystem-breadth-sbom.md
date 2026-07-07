# ADR-0027: Ecosystem breadth + SBOM — multi-format lockfile parsing, CycloneDX export, integrity cross-check

**Status:** Accepted (Phase 14)
**Date:** 2026-07-07

## Context

ADR-0020 shipped `sentinel audit-tree` as a whole-tree gate, but it spoke only
one dialect: npm's `package-lock.json` v2/v3 `packages` map. Its Deferred
list named the gap explicitly — yarn/pnpm lockfiles, an SBOM export, a
lockfile-vs-served integrity cross-check, and an opt-in fail-on-error gate —
and left all four for a later phase. That gap has two real costs. First,
any team on yarn or pnpm (a large share of the npm ecosystem) gets no
whole-tree gate at all; `audit-tree` silently only helps npm users. Second,
without an SBOM export, `audit-tree`'s findings live only in Sentinel's own
JSON/console output — nothing an operator's existing SBOM tooling (vuln
scanners, license auditors, procurement questionnaires) can consume. Phase 14
closes both: it is breadth work, not new detection — every underlying
per-package audit path (rules, scoring, provenance) is untouched.

## Decision

- **`parseAnyLockfile(raw, { filename?, omitDev? })`** (`packages/core/src/lockfile.ts`)
  is the single entry point the CLI calls. It dispatches by filename suffix
  first (`package-lock.json`/`npm-shrinkwrap.json`, `yarn.lock`,
  `pnpm-lock.yaml`), falling back to a content sniff (JSON object → npm;
  `# yarn lockfile v1` or a `__metadata:`/`resolution:`/`@npm:` combination →
  yarn; a `lockfileVersion:` line → pnpm) when no filename is given or the
  suffix doesn't match. An unrecognized format throws a clear, actionable
  error rather than guessing. All three format parsers — `parseLockfile`
  (npm), `parseYarnLock` (yarn), `parsePnpmLock` (pnpm) — return the same
  `Coordinate[]` (`{name, version, integrity?}`), deduped by `name@version`
  and sorted, so every downstream consumer (the proxy route, the SBOM
  projection, tests) stays format-agnostic.
- **Yarn gets two parsers behind one dispatcher.** `parseYarnLock` regex-sniffs
  which yarn generation it's holding: a bespoke line-oriented parser for v1's
  custom text format (`name@range:` headers, indented `version`/`integrity`
  fields — no existing parser handles this shape), and `yaml.parse` over
  berry's YAML body for v2+ (keys are `name@npm:range`, entries carry
  `version` but no SRI-shaped checksum).
- **pnpm gets one parser across lockfile versions.** `parsePnpmLock` reads
  `lockfileVersion` to choose the key shape — v5's `/name/version` versus
  v6/v9's `name@version` — and strips the peer-dependency suffix
  (`(a@1)(b@2)`) either way before splitting on the last `@` or `/`.
  Integrity comes from `packages[key].resolution.integrity`.
- **The `yaml` dependency (`^2.9.0`) is added to `@sentinel/core` only.**
  Both pnpm's and yarn-berry's lockfiles are YAML; npm's and yarn v1's are
  not. No other workspace package needs a YAML parser, so the dependency
  stays scoped to where the parsing logic actually lives.
- **`toCycloneDX(tree, { now })`** (`packages/core/src/sbom.ts`) projects a
  `TreeAuditResult` into a CycloneDX 1.6 JSON BOM: one `library` component
  per package, `purl` as `pkg:npm/<name>@<version>` (scoped names `%40`-encode
  the `@`), and Sentinel's verdict/score/top-finding/integrity-mismatch
  attached as `sentinel:*` custom properties rather than invented CycloneDX
  fields — the BOM stays spec-valid for any CycloneDX consumer while still
  carrying Sentinel's signal for tools that know to look for it. Wired into
  the CLI as `audit-tree --sbom <file>`, written from the same tree result
  the console/JSON output already renders.
- **The integrity cross-check reuses Phase 9's recomputed served hash.**
  The `/-/audit-tree` route already calls `auditVersion`, whose report
  carries `meta.integrity` — the hash Sentinel actually recomputed from the
  bytes it served (`actualIntegrity`, ADR-0022), not a claimed value. When
  the caller's lockfile coordinate carries an `integrity` field, the route
  compares it against `report.meta.integrity`; a mismatch forces that row to
  `block`, sets `integrityMismatch: true`, and injects a
  `lockfile-integrity-mismatch` top finding — the closest thing `audit-tree`
  has to substitution/tampering detection between what a team's lockfile
  pinned and what the registry serves today. Both `TreePackageRow` and
  `TreeAggregate` gained an `integrityMismatch` field (row: boolean;
  aggregate: count) so the CLI's summary and the SBOM can both surface it.
  When either side has no integrity to compare (yarn-berry's non-SRI
  checksum, or a claimed package with no integrity in the lockfile at all),
  the row is left alone — the check only ever fires on a genuine disagreement
  between two present SRI-shaped hashes, never on absence.
- **`--fail-on-error` is opt-in, not the default.** `aggregateTree`'s
  `failOnError` option (default `false`, preserving ADR-0020's fail-open
  stance on unresolvable packages) now also gates the tree when any row is an
  `error` row, if the caller asks for it. The CLI threads `--fail-on-error`
  into the request body; the proxy — which already owns the aggregate — is
  the one that applies it, so the CLI never re-derives the rollup client-side.

## Determinism (invariant #1 untouched)

Every function this phase adds is pure. The three lockfile parsers and
`parseAnyLockfile` are total functions of their input text (and optional
filename/omitDev flags) with no I/O beyond the string they're handed.
`toCycloneDX` takes its only time-varying input as an injected `now`
parameter rather than reading the clock itself, matching the injected-clock
pattern ADR-0022 established for `trust-root-stale`. None of this touches
the per-package score path: `runAudit`, `score()`, and the rule set are
byte-for-byte what they were before this phase. This is tree/CLI tooling
layered on top of already-computed, already-deterministic per-package
reports — the pinned `scoring is deterministic across runs` test is
unaffected because nothing in it exercises lockfile parsing or SBOM export.

## Consequences

- One new dependency, `yaml`, scoped to `@sentinel/core` — the only package
  that parses YAML-format lockfiles.
- Yarn-berry's checksum field is not an SRI-shaped hash, so those rows never
  participate in the integrity cross-check — a berry-only team gets the
  broader lockfile-format coverage and SBOM export from this phase, but not
  the mismatch detection, until berry's checksum format changes or a
  translation is added.
- The SBOM is a flat, unsigned component list: one `library` entry per
  package with no dependency-graph edges between them and no cryptographic
  signature over the document itself. It is useful as an inventory and as a
  vehicle for Sentinel's verdict/score signal, but it is not (yet) a
  structural SBOM a consumer could use to reconstruct the dependency graph,
  nor a provable, tamper-evident artifact.

## Deferred

- **Bun lockfiles** (`bun.lock`/`bun.lockb`) — a fourth ecosystem format with
  no parser here yet.
- **SPDX output** — CycloneDX only; no SPDX projection of the same tree.
- **CycloneDX `vulnerabilities` array** — the BOM carries Sentinel's
  verdict/score as custom properties, not structured CVE-shaped vulnerability
  records a VEX-aware consumer would expect.
- **SBOM signing** — the BOM is written as plain JSON; no detached signature,
  in-toto attestation, or Sigstore bundle over the document.
- **Transitive graph edges in the SBOM** — components are a flat list; no
  `dependencies` array recording which package resolved which.

## Rejected

- **Regex-based pnpm key extraction without the pnpm lockfile's YAML
  structure** — rejected: pnpm's peer-dependency suffixes
  (`(a@1)(b@2)(c@3)...`) and the v5-vs-v6/v9 key-shape change make a
  hand-rolled regex brittle against real-world lockfiles; parsing the YAML
  properly and stripping the suffix systematically is barely more code and
  doesn't silently misparse edge cases a regex would miss.
- **Shipping npm-only and leaving yarn/pnpm unsupported** — rejected: this is
  exactly the gap ADR-0020 named and deferred. A whole-tree gate that only
  works for one of three major npm-ecosystem package managers leaves a large
  share of real teams with no coverage at all; the whole point of this phase
  is closing that list.

Extends ADR-0020 (whole-tree audit — closes its yarn/pnpm/SBOM/integrity-check/
fail-on-error deferred items), ADR-0004 (integrity-hash cache key — the cross-check
reuses the same `dist.integrity`-keyed, recomputed-hash contract rather than
inventing a second notion of integrity), and ADR-0002 (deterministic scoring —
parsing and SBOM export are pure projections of already-deterministic audit
output; the score path itself is untouched). Supersedes nothing.

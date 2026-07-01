# Sentinel Phase 7 — whole-tree lockfile audit (`sentinel audit-tree`) (design)

**Date:** 2026-07-01
**Status:** Approved (brainstorming) — ready for implementation planning
**Implements:** a project-wide pre-install / CI gate over an entire resolved dependency tree,
composing the existing per-tarball audit engine, enterprise policy, and integrity cache.
**Sequence context:** Phase 1 (auditing proxy + scoring), Phase 2 (approval gate, signed
policy, private registry), Phases 3–5 (macOS/Linux sandbox enforcement), Phase 6
(`install --enforce`) are built. Everything to date audits or contains **one package at a
time** — on a tarball request or a single unpacked directory. Phase 7 lifts the same engine to
the **whole dependency graph** in a single command, with an aggregate verdict and a CI exit code.

---

## 1. Goal & threat model

Today an audit verdict exists only for a package you explicitly `sentinel audit`, or as a
side effect of the proxy serving a tarball during install. There is no single-pass answer to
the question a CI pipeline actually asks: **"is my whole resolved dependency tree acceptable
under policy, yes or no?"** A malicious transitive dependency deep in the graph is scored the
same as any other tarball, but nothing rolls those per-package verdicts into one gate with a
process exit code.

Phase 7 closes that: `sentinel audit-tree [lockfile]` reads a resolved lockfile, audits every
package through the proxy under the loaded enterprise policy, rolls the results into an
**aggregate verdict**, and **exits non-zero when the policy gate trips** — the contract a CI
step needs. No new scoring logic; pure composition of the existing engine.

**Success criteria**
1. A lockfile whose tree is entirely benign audits to an **allow** aggregate and the command
   **exits 0**.
2. A lockfile containing a package that scores **block** produces a **gated** aggregate and the
   command **exits non-zero** — the package is named in the output.
3. **Deterministic:** the same lockfile + same policy ⇒ the same aggregate verdict and the same
   sorted per-package output, independent of fan-out/concurrency order (invariant #1).
4. A package the upstream **cannot resolve** (404 / network) is surfaced as a distinct
   per-package `error` entry and does **not** crash the run (invariant #6 spirit); it does not
   silently pass.
5. Scoring is **full-mode per package** — the ADR-0008 diff multiplier does not apply to a
   pinned set.
6. Hermetic: tests run the proxy over `LocalFixtureUpstream` against a committed fixture
   lockfile; the synthetic-malicious fixture is scored **as text and never executed**.

---

## 2. Architecture — two moving parts

The lockfile gives `(name, version, integrity, resolved-url)` but **not tarball bytes**, and
scoring needs the fileset. Bytes + scoring come from the **proxy** (decided in brainstorming
over an offline/local-cache alternative): it already owns byte acquisition (`upstream.getTarball`),
the enterprise policy, the integrity cache, and private-store handling. A tree audit run right
after `sentinel install` is therefore mostly cache hits (cache key = integrity, which the
lockfile already carries).

### 2.1 CLI — `sentinel audit-tree [lockfile]`

- **Argument:** optional lockfile path, defaulting to `./package-lock.json`.
- **Lockfile parsing lives here** (format knowledge is a client concern): parse npm
  `package-lock.json` **v2/v3** — the `packages` map keyed by install path. Produce a deduped
  list of `{name, version, integrity}` coordinates. **Skip** the root `""` entry and any
  `link:` / `file:` entries (local, not registry-served). Derive `name` from the entry's
  `name` field or the trailing `node_modules/<name>` path segment.
- **`--omit dev`** excludes entries marked `"dev": true` (mirrors npm's `--omit`); default
  audits every registry-resolved package in the lockfile.
- **`--json`** emits the full server payload; **`--proxy <url>`** as on the other commands.
- POSTs the coordinate list to the proxy, renders the response, and **sets its exit code from
  the aggregate `gated` flag**.

### 2.2 Proxy — `POST /-/audit-tree`

- **Request body:** `{ packages: [{ name, version, integrity? }, ...] }`.
- Fans out with **bounded concurrency**, reusing the existing `auditVersion()` path — so the
  integrity cache, enterprise policy, and private-store handling all apply unchanged. This is
  an explicit `/-/`-namespaced batch endpoint doing N fetches; it is **not** on the inline gate
  path, so invariant #3 (sync gate stays cheap) is preserved.
- Computes the **aggregate + gate decision server-side** (where the policy lives) and returns:

  ```json
  {
    "aggregate": { "verdict": "allow|warn|block", "gated": false, "counts": {"allow": 0, "warn": 0, "block": 0, "error": 0} },
    "packages": [ /* per-package AuditReport, plus {name, version, status:"error", error} for unresolved */ ]
  }
  ```
- `packages` is **sorted by `name@version`** so output is order-independent.

---

## 3. Aggregation & the gate — as policy data (invariant #1)

- Each package keeps its existing per-package verdict from `score()` under the active policy.
- The tree verdict is **worst-case-wins**: `block` ⊐ `warn` ⊐ `allow`.
- A new **`treeGate` field in `POLICY`** (`packages/core/src/score.ts`) names the verdict level
  at which the gate trips — **default `"block"`**. An enterprise policy can set it to `"warn"`
  to fail harder. The threshold is **data, not code** — no hardcoded verdict comparison in a
  code path.
- `gated = worstVerdict is at or above treeGate`. The aggregate is computed by pure reduction
  over the sorted per-package verdicts, so it does not depend on fetch order (invariant #1).
- `error` entries (§4) are counted separately and do **not** contribute to `worstVerdict`.

---

## 4. Error handling

A package the upstream cannot resolve (404, network failure, or a `private-package-not-found`)
becomes a per-package entry `{ name, version, status: "error", error: "<message>" }` rather
than aborting the whole tree — consistent with invariant #6 (an individual failure must not
take down the run). These are surfaced loudly in output and counted in `counts.error`, but they
do **not** set the aggregate verdict and do **not** by themselves trip the gate. (Treating an
unresolved dependency as a hard failure is a plausible future policy knob; out of scope here.)

---

## 5. Output & exit code

- **Human (default):** a table sorted by `name@version` — verdict, score, top finding per row —
  followed by a summary line (`N packages: X allow, Y warn, Z block, E error`) and the aggregate
  verdict. Errors are listed distinctly.
- **`--json`:** the full server payload verbatim.
- **Exit code:** `0` when `gated === false`; **non-zero** when `gated === true`. This is the CI
  contract — a pipeline step fails the build on a gated tree.

---

## 6. Testing (hermetic)

Fixtures already carry real `integrity` hashes in `fixtures/registry.json`, so a hermetic
`package-lock.json` referencing existing fixture packages is constructable and resolves against
`LocalFixtureUpstream`.

- **Benign tree fixture** → aggregate `allow`, `gated: false`, exit 0.
- **Malicious-containing tree fixture** (includes a synthetic-malicious fixture package) →
  aggregate `block`, `gated: true`, non-zero exit; the offending package is named.
- **Determinism:** two runs over the same lockfile produce identical aggregate + sorted output.
- **Error surfacing:** a coordinate absent from the fixture registry appears as a per-package
  `error` and does not crash the run.
- **`--omit dev`:** a dev-marked entry is excluded when the flag is set, included by default.
- **Policy knob:** a policy with `treeGate: "warn"` gates a tree whose worst verdict is `warn`.

Tests stay hermetic (CLAUDE.md): `LocalFixtureUpstream` only, never live npm. The
synthetic-malicious fixture is scored as text and never executed.

---

## 7. Non-goals (deferred)

- **CycloneDX SBOM output** — a separate output format, its own later phase.
- **Lockfile-integrity-vs-served-integrity tamper detection** — comparing the lockfile's
  `integrity` against the bytes the upstream actually serves is a genuine tamper check and cheap,
  but out of scope for this slice (candidate follow-up).
- **yarn / pnpm lockfiles** — npm `package-lock.json` v2/v3 only for now.
- **Transitive resolution from a bare `package.json`** — we consume the *resolved* lockfile; we
  do not perform dependency resolution.
- **Treating unresolved dependencies as a hard gate failure** — surfaced as errors, not gated.

---

## 8. New ADR

**ADR-0020 — whole-tree audit via lockfile fan-out + server-side aggregate.** Records:
the proxy-backed byte-source choice (vs offline/local-cache), the split of lockfile-format
parsing (client) from aggregation + gate (server, where policy lives), and `treeGate` as
per-policy data rather than a hardcoded threshold.

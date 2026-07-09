# OSS Launch Prep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `git-agentic/pkg-registry` (Sentinel) ready for public OSS launch — all community/security files, CodeQL, issue templates, README freshness, repo settings, a full-history secrets scan, and a go-public checklist — everything except the visibility flip, which the operator does.

**Architecture:** Pure docs/workflows/settings work on a branch `oss-launch-prep`; zero source-code changes. Long canonical texts (Apache-2.0, Contributor Covenant 2.1) are fetched from their canonical URLs and verified; everything else is authored inline. Spec: `docs/superpowers/specs/2026-07-09-oss-launch-design.md`.

**Tech Stack:** Markdown, GitHub Actions YAML, `gh` CLI, gitleaks, actionlint.

## Global Constraints

- **Zero source-code changes** — only docs, workflows, templates, `.gitignore`, and GitHub settings.
- **No history rewriting of any kind.** If the secrets scan finds anything, STOP and escalate to the operator.
- **Do NOT flip repo visibility.** The operator flips PRIVATE → PUBLIC using the checklist (Task 10's deliverable).
- Repo name stays `pkg-registry`; license is Apache-2.0; homepage is `https://git-agentic.com/sentinel`.
- `docs/superpowers/` planning docs stay committed (public at launch).
- Work on branch `oss-launch-prep`; finish with a pushed branch + PR; the operator merges (`--no-ff` locally, per their flow).
- Definition of done: `npm run build` clean, `npm test` green (661 on darwin per CLAUDE.md), gitleaks clean or escalated, actionlint clean on new YAML, `gh repo view` reads back the settings.

---

### Task 1: Branch + hygiene (.gitignore, stale README test count)

**Files:**
- Modify: `.gitignore`
- Modify: `README.md:33`

**Interfaces:**
- Produces: branch `oss-launch-prep` that every later task commits to.

- [ ] **Step 1: Create the branch**

```bash
git checkout -b oss-launch-prep
```

- [ ] **Step 2: Ignore the untracked internal scratch dir**

Append to `.gitignore` (it currently ends with `sentinel-sbom.json`):

```
.superpowers/
```

- [ ] **Step 3: Fix the stale test count on README.md line 33**

Replace:

```
npm test             # 308 tests: engine + end-to-end proxy (see CLAUDE.md for the exact/skip breakdown)
```

with:

```
npm test             # engine + end-to-end proxy — see CLAUDE.md for the current count and skip breakdown
```

(The count drifts every phase; CLAUDE.md is the source of truth. Don't hardcode a number here.)

- [ ] **Step 4: Verify**

Run: `git check-ignore .superpowers/ && grep -c "308" README.md`
Expected: prints `.superpowers/`; grep prints `0` (exit 1 from grep -c is fine if it prints 0 — use `grep -c "308 tests" README.md || true`).

- [ ] **Step 5: Commit**

```bash
git add .gitignore README.md
git commit -m "chore: gitignore .superpowers/, unpin stale README test count"
```

---

### Task 2: LICENSE (Apache-2.0)

**Files:**
- Create: `LICENSE`

**Interfaces:**
- Produces: `LICENSE` at repo root; README badge (Task 8) and repo license detection depend on it.

- [ ] **Step 1: Fetch canonical text**

```bash
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
```

- [ ] **Step 2: Verify it is the real license**

Run: `wc -l LICENSE && head -2 LICENSE && grep -c "Apache License" LICENSE`
Expected: ~202 lines; first non-blank lines contain `Apache License` and `Version 2.0, January 2004`. If the fetch failed or returned HTML, STOP — do not commit a corrupt LICENSE.

Note: Apache-2.0's appendix boilerplate (`Copyright [yyyy] [name of copyright owner]`) stays as-is in LICENSE — that is standard practice; the canonical file is committed unmodified. GitHub's license detection requires the unmodified text.

- [ ] **Step 3: Commit**

```bash
git add LICENSE
git commit -m "chore: add Apache-2.0 LICENSE"
```

---

### Task 3: CODE_OF_CONDUCT.md (Contributor Covenant 2.1)

**Files:**
- Create: `CODE_OF_CONDUCT.md`

- [ ] **Step 1: Fetch canonical text**

```bash
curl -fsSL https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md -o CODE_OF_CONDUCT.md
```

- [ ] **Step 2: Fill the enforcement-contact placeholder (no email)**

The canonical text contains `[INSERT CONTACT METHOD]`. Replace that exact string with:

```
a private report to the repository maintainers via GitHub (open a security advisory report from the repo's Security tab, or use GitHub's "Report content" flow)
```

- [ ] **Step 3: Verify**

Run: `grep -c "INSERT CONTACT METHOD" CODE_OF_CONDUCT.md || true; head -3 CODE_OF_CONDUCT.md`
Expected: `0` remaining placeholders; header is `# Contributor Covenant Code of Conduct`. If the fetch returned HTML instead of markdown (site sometimes serves the page), fall back to:

```bash
curl -fsSL https://raw.githubusercontent.com/EthicalSource/contributor_covenant/release/content/version/2/1/code_of_conduct.md -o CODE_OF_CONDUCT.md
```

then strip any YAML frontmatter block (`---`…`---`) at the top and redo Step 2.

- [ ] **Step 4: Commit**

```bash
git add CODE_OF_CONDUCT.md
git commit -m "chore: add Contributor Covenant 2.1 code of conduct"
```

---

### Task 4: SECURITY.md

**Files:**
- Create: `SECURITY.md`

**Interfaces:**
- Consumes: fixture safety rules live in CLAUDE.md + CONTRIBUTING.md (Task 5 links back here; a `[fixture safety rules]` link targets CONTRIBUTING.md#fixture-safety-rules).

- [ ] **Step 1: Write the file**

Create `SECURITY.md` with exactly this content:

```markdown
# Security Policy

Sentinel is a security product — an auditing proxy, policy gate, and install
sandbox for the npm ecosystem. We treat reports against it accordingly.

## Supported versions

Sentinel is pre-1.0. Only the tip of `main` is supported; there are no
maintained release branches and no published npm packages yet.

## Reporting a vulnerability

**Please do not open a public issue for an exploitable flaw.**

Use GitHub private vulnerability reporting: go to the repository's
**Security** tab → **Report a vulnerability**. Reports go privately to the
maintainers; we'll acknowledge within a few days and coordinate a fix and
disclosure with you.

## What counts as a vulnerability here

In scope (report privately):

- A **sandbox escape** — a lifecycle script escaping the Seatbelt/bubblewrap
  confinement, reading denied paths, or reaching denied capabilities.
- A **gate bypass** — the proxy serving a tarball whose verdict is `block`,
  or a way to make an installer skip the gate it was configured to use.
- A **fail-open scoring path** — input that makes the audit engine crash into
  an `allow`, skews the deterministic score, or poisons the integrity-keyed
  cache.
- A **control-plane auth bypass** — minting/forging role tokens, mutating
  approvals/violations/policy without the required role, or escalating an
  `agent` token past the request-not-grant boundary.
- **SSRF / trust-boundary escapes** — steering the proxy's outbound fetches
  off the configured registry origins, or abusing the packument rewrite.

Not an advisory (use a public issue instead):

- A heuristic rule **missing a malicious sample** or **flagging a benign
  one** — that's a detection gap, not an exploit. Open a *Detection gap*
  issue. Detection heuristics are signal, not proof; misses are expected
  and tracked openly.
- Vulnerabilities in third-party packages Sentinel audits. Report those to
  the package's own maintainers (Sentinel is the smoke detector, not the
  fire).

## About the malware fixtures in this repo

`fixtures/malicious/**` contains **synthetic, inert** malware lookalikes used
to test the scoring engine. They carry a `SYNTHETIC FIXTURE` header, use
RFC 5737 documentation IPs only, are scored **as text**, and are never
executed — by tests, by the demo, or by anything else in this repo. Finding
scary-looking strings there is by design and is not a vulnerability. See the
fixture safety rules in [CONTRIBUTING.md](./CONTRIBUTING.md#fixture-safety-rules).
```

- [ ] **Step 2: Verify**

Run: `grep -c "Report a vulnerability" SECURITY.md`
Expected: `1` (the Security-tab instruction; the heading itself says "Reporting").

- [ ] **Step 3: Commit**

```bash
git add SECURITY.md
git commit -m "docs: add SECURITY.md (private vulnerability reporting, scope, fixture note)"
```

---

### Task 5: CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

**Interfaces:**
- Produces: anchor `#fixture-safety-rules` that SECURITY.md (Task 4) links to. Heading text must stay `## Fixture safety rules`.

- [ ] **Step 1: Write the file**

Create `CONTRIBUTING.md` with exactly this content:

```markdown
# Contributing to Sentinel

Thanks for helping build an agent-auditable security layer for npm. This page
is the practical guide; the design lives in [ARCHITECTURE.md](./ARCHITECTURE.md),
the decision log in [docs/adr/](./docs/adr/), and the working agreement (the
invariants that make this a security product rather than a linter) in
[CLAUDE.md](./CLAUDE.md).

## Getting started

Node **>= 22** (developed against Node 24, Active LTS).

```bash
npm install          # workspace deps
npm run build        # tsc --build across all packages
npm test             # engine + end-to-end proxy (hermetic; never hits live npm)
npm run demo         # offline malware-detection walkthrough
```

The exact test count and platform skip breakdown are documented in
[CLAUDE.md](./CLAUDE.md) — it changes as the project grows; CLAUDE.md is the
source of truth. Tests are hermetic: they use `LocalFixtureUpstream` against
packed local fixtures (`npm run fixtures`, run automatically by `pretest`).

## Fixture safety rules

**Never add live malware to this repo.** Malicious fixtures must be:

- **synthetic and inert** — written for this repo, doing nothing when run;
- marked with a `SYNTHETIC FIXTURE` header comment;
- using **RFC 5737 documentation IPs only** (`198.51.100.0/24`,
  `203.0.113.0/24`) for any "exfil" targets.

They are scored **as text** and never executed. Fixtures live in
`fixtures/<benign|malicious>/<name>/<version>/package/`; after editing, re-run
`npm run fixtures` to re-pack the `.tgz` files and `fixtures/registry.json`.

A PR containing real-world malicious code, live C2 addresses, or anything
copied from an actual campaign will be closed. If you want Sentinel to catch a
real-world pattern, describe the *pattern* in an issue and we'll build a
synthetic fixture for it.

## Non-negotiable invariants

Summarized — the full list with rationale is in [CLAUDE.md](./CLAUDE.md):

1. Scoring is **deterministic** given a policy; the LLM never sets the score.
2. The inline gate is **sync + cheap**; nothing slow on the request path.
3. Caches key on the **integrity hash**, never on version alone.
4. The proxy is **transparent** — packuments pass through, only
   `dist.tarball` is rewritten.
5. Rules **fail open individually**; the audit never crashes an install.
6. Claimed private namespaces are **fail-closed** — served only from the
   private store.

A PR that breaks one of these will be asked to change approach, however clean
the code. If you believe an invariant itself is wrong, that's an ADR
discussion, not a code change.

## Adding a detection rule

Create `packages/core/src/rules/<id>.ts` exporting a `Rule` (a pure
`(AuditInput) => Finding[]`), register it in `packages/core/src/rules/index.ts`,
and use `mkFinding()` from `rules/util.ts` so the diff multiplier and policy
weights apply consistently — don't compute weights by hand. Policy weights and
verdict thresholds live in `POLICY` in `packages/core/src/score.ts`, nowhere
else. Every rule change needs a test proving the new behavior, and the
malicious fixtures must still be **blocked**.

## ADRs

Design decisions are recorded in [docs/adr/](./docs/adr/). Never edit an
Accepted ADR to reverse it — supersede it with a new one. If your change
alters a design invariant, update ARCHITECTURE.md and add/supersede an ADR in
the same PR.

## Issues & triage

Bug reports, feature requests, and **detection gaps** (missed detection or
false positive) each have an issue template. Maintainers triage with the
labels `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`,
and `wontfix` — see [docs/agents/triage-labels.md](./docs/agents/triage-labels.md).

Security vulnerabilities: **not** a public issue — see
[SECURITY.md](./SECURITY.md).

## Definition of done for a PR

`npm run build` clean, `npm test` green, new behavior covered by a test, and
the malicious fixtures still blocked. CI runs the suite on Linux (Node 22 +
24) including the bubblewrap sandbox enforcement path; macOS Seatbelt
enforcement is exercised on maintainers' machines.
```

- [ ] **Step 2: Verify the cross-link anchors resolve**

Run: `grep -c "^## Fixture safety rules" CONTRIBUTING.md && grep -c "CONTRIBUTING.md#fixture-safety-rules" SECURITY.md`
Expected: `1` and `1`.

- [ ] **Step 3: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING.md (quickstart, fixture safety, invariants, ADR + triage process)"
```

---

### Task 6: Threat model (`sentinel-threat-model.md`)

**Files:**
- Create: `sentinel-threat-model.md` (repo root — placement mirrors `git.agentic-threat-model.md` in the reference repo)

**Interfaces:**
- Consumes: ARCHITECTURE.md, docs/adr/0001–0038. **No new analysis** — this is the existing decision log reframed for an external security reader.

- [ ] **Step 1: Generate the threat model**

If the `security-threat-model` skill is available in your session, invoke it
scoped to this repo and write the output to `sentinel-threat-model.md`.
Otherwise author it directly. Either way the document MUST contain these
sections with this substance (source material in parentheses):

1. **System overview & trust boundaries** — a diagram-as-text of the five
   boundaries: (a) npm upstream ↔ proxy (tarball origin pinning,
   ADR-0036); (b) proxy ↔ installer (verdict headers, 403 gate);
   (c) installer ↔ sandboxed lifecycle scripts (Seatbelt/bwrap
   deny-by-default, ADR-0016/0018/0038); (d) control plane ↔ roles
   (signed Ed25519 role tokens, request-not-grant, ADR-0024/0025);
   (e) operator trust material (policy signing keys, pinned provenance
   roots in `packages/core/trust/`, `NPM_SIGNING_KEYS` — all static
   inputs, never fetched at audit time).
2. **Assets** — developer credentials/env vars; verdict integrity; policy
   signing keys; the private-namespace store; audit history; the
   integrity-keyed cache.
3. **Attacker capabilities & abuse paths** — one subsection each: malicious
   package author (scored pre-install); compromised maintainer/release
   (release-anomaly + capability-novelty signals, ADR-0029); name squatter
   (typosquat + dependency-confusion, ADR-0026; fail-closed private
   namespaces, ADR-0010/0015); known-bad releases (advisory/vuln corpora,
   ADR-0034/0035); malicious packument steering fetches (SSRF — closed,
   ADR-0036); Host-header spoofing (421 — closed, ADR-0036); resource
   exhaustion (byte caps, tree cap, rate limiter, ADR-0037); agent holding
   a control-plane token (403 past request-not-grant, ADR-0025); script
   escaping the sandbox (deny-by-default writes + $HOME reads, SENSITIVE
   carve-outs, ADR-0038).
4. **Accepted limitations** — verbatim honesty, one bullet each:
   heuristics are signal, not proof (misses expected — detection-gap
   issues); swallowed-denial telemetry evasion (containment unchanged,
   ADR-0023); Seatbelt-vs-bwrap telemetry asymmetry (EPERM/confirmed vs
   ENOENT/unclassified, ADR-0038); LLM enrichment advisory-only, never the
   verdict (ADR-0002); deliberate fail-open stances (per-rule fail-open,
   unresolvable tree rows without `--fail-on-error`, attestation fetch);
   network MITM out of scope (TLS assumed).
5. **Out of scope** — runtime app security of installed packages after a
   verdict `allow`; npm account security; the operator's own key hygiene.

- [ ] **Step 2: Verify structure + claims**

Run: `grep -c "^## " sentinel-threat-model.md`
Expected: >= 5 top sections. Spot-check every ADR number cited actually
exists in `docs/adr/` (`ls docs/adr | grep -o '^00[0-9][0-9]'`). Any claim
about behavior must trace to ARCHITECTURE.md or an ADR — no aspirational
statements.

- [ ] **Step 3: Commit**

```bash
git add sentinel-threat-model.md
git commit -m "docs: add public threat model (boundaries, abuse paths, accepted limitations)"
```

---

### Task 7: CodeQL workflow + issue templates

**Files:**
- Create: `.github/workflows/codeql.yml`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`
- Create: `.github/ISSUE_TEMPLATE/detection-gap.yml`
- Create: `.github/ISSUE_TEMPLATE/feature_request.yml`
- Create: `.github/ISSUE_TEMPLATE/config.yml`

- [ ] **Step 1: Write `.github/workflows/codeql.yml`**

```yaml
name: codeql

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "30 6 * * 1"

jobs:
  analyze:
    name: analyze (${{ matrix.language }})
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      actions: read
    strategy:
      fail-fast: false
      matrix:
        language: [javascript-typescript]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

- [ ] **Step 2: Write `.github/ISSUE_TEMPLATE/bug_report.yml`**

```yaml
name: Bug report
description: Something is broken (crash, wrong behavior, docs mismatch)
labels: [needs-triage]
body:
  - type: textarea
    id: what
    attributes:
      label: What happened?
      description: What did you do, what did you expect, what happened instead?
    validations:
      required: true
  - type: textarea
    id: repro
    attributes:
      label: Reproduction
      description: Exact commands / config. If it involves the proxy, include the relevant SENTINEL_* env vars (redact secrets).
      render: shell
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Version / commit
      placeholder: main @ <sha>, Node 24.x, macOS/Linux
    validations:
      required: true
  - type: markdown
    attributes:
      value: >
        **Security vulnerabilities** (sandbox escape, gate bypass, auth
        bypass): do not file an issue — use private vulnerability reporting
        via the Security tab. See SECURITY.md.
```

- [ ] **Step 3: Write `.github/ISSUE_TEMPLATE/detection-gap.yml`**

```yaml
name: Detection gap
description: A package that should have been flagged (or was wrongly flagged)
labels: [needs-triage]
body:
  - type: dropdown
    id: kind
    attributes:
      label: Kind
      options:
        - Missed detection (should have been flagged, wasn't)
        - False positive (benign package was flagged)
    validations:
      required: true
  - type: input
    id: coordinate
    attributes:
      label: Package name and version
      placeholder: some-package@1.2.3
    validations:
      required: true
  - type: input
    id: integrity
    attributes:
      label: dist.integrity (if known)
      placeholder: sha512-...
  - type: textarea
    id: expected
    attributes:
      label: Expected vs actual verdict
      description: What did Sentinel say (score, verdict, findings) and what should it have said? Paste the audit output if you have it.
    validations:
      required: true
  - type: textarea
    id: pattern
    attributes:
      label: The pattern (for missed detections)
      description: >
        Describe the malicious *pattern* in prose. Do NOT paste live malware,
        real C2 addresses, or working exploit code — we build synthetic, inert
        fixtures from descriptions (see CONTRIBUTING.md, "Fixture safety rules").
```

- [ ] **Step 4: Write `.github/ISSUE_TEMPLATE/feature_request.yml`**

```yaml
name: Feature request
description: Propose a capability, rule, integration, or policy control
labels: [needs-triage]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What can't you do today? Who hits this (human, CI, agent)?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed behavior
      description: What should Sentinel do? Note any invariant it touches (see CLAUDE.md) — e.g. nothing slow may go on the inline gate.
    validations:
      required: true
```

- [ ] **Step 5: Write `.github/ISSUE_TEMPLATE/config.yml`**

```yaml
blank_issues_enabled: false
contact_links:
  - name: Report a security vulnerability
    url: https://github.com/git-agentic/pkg-registry/security/advisories/new
    about: Sandbox escapes, gate bypasses, auth bypasses — privately, please. See SECURITY.md.
```

- [ ] **Step 6: Validate YAML**

```bash
brew install actionlint 2>/dev/null || true
actionlint .github/workflows/codeql.yml
node -e 'const y=require("yaml");const fs=require("fs");for (const f of ["bug_report","detection-gap","feature_request","config"]) y.parse(fs.readFileSync(`.github/ISSUE_TEMPLATE/${f}.yml`,"utf8")); console.log("yaml ok")' 
```

Expected: actionlint exits 0 with no output; `yaml ok`. (`yaml` is already a dependency of `@sentinel/core`, so `require("yaml")` resolves from the workspace root; if it doesn't, run the one-liner with `cwd` at `packages/core`.)

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/codeql.yml .github/ISSUE_TEMPLATE/
git commit -m "ci: add CodeQL workflow and issue templates (bug, detection-gap, feature)"
```

---

### Task 8: README status section, homepage link, badges

**Files:**
- Modify: `README.md` (top: after the H1 line `# Sentinel`, and after the intro quote block)

- [ ] **Step 1: Add badges directly under the H1**

Immediately after the line `# Sentinel`, insert a blank line then:

```markdown
[![ci](https://github.com/git-agentic/pkg-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/git-agentic/pkg-registry/actions/workflows/ci.yml)
[![codeql](https://github.com/git-agentic/pkg-registry/actions/workflows/codeql.yml/badge.svg)](https://github.com/git-agentic/pkg-registry/actions/workflows/codeql.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
```

- [ ] **Step 2: Add a Status section**

Immediately after the paragraph that ends `…stack justification).` (the
"See **[ARCHITECTURE.md](./ARCHITECTURE.md)**…" paragraph, before the `---`
that precedes `## Quickstart`), insert:

```markdown
## Status

**Pre-1.0; built through Phase 25 (deny-by-default install sandbox).** The
proxy, policy gate, sandbox (macOS Seatbelt / Linux bubblewrap), CLI, MCP
server, and GitHub Action work end-to-end and are covered by the full test
suite on macOS and Linux CI — but this has not yet been hardened by
production use, and APIs may change without notice. **No npm packages are
published yet**: build from source (Quickstart below). Threat model:
[sentinel-threat-model.md](./sentinel-threat-model.md) · Homepage:
[git-agentic.com/sentinel](https://git-agentic.com/sentinel)
```

- [ ] **Step 3: Verify rendering-critical details**

Run: `grep -n "badge.svg\|git-agentic.com/sentinel\|## Status" README.md | head`
Expected: three badge lines right after the H1, one `## Status` heading, one homepage link. Confirm the quote block above Status is not broken (line starting `> Why:` still renders as one blockquote).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: README badges, Status section, homepage link"
```

---

### Task 9: Repo settings via gh (everything except the flip)

**Files:** none (GitHub API state only)

- [ ] **Step 1: Set description + homepage**

```bash
gh repo edit git-agentic/pkg-registry \
  --description "Agent-auditable security layer for npm — auditing proxy, deny-by-default install sandbox, provenance & signature verification, SBOM + signed attestations, MCP surface." \
  --homepage "https://git-agentic.com/sentinel"
```

- [ ] **Step 2: Set topics**

```bash
gh repo edit git-agentic/pkg-registry \
  --add-topic npm --add-topic supply-chain-security --add-topic security \
  --add-topic sandbox --add-topic sbom --add-topic provenance \
  --add-topic mcp --add-topic ai-agents
```

- [ ] **Step 3: Read back and verify**

```bash
gh repo view git-agentic/pkg-registry --json description,homepageUrl,repositoryTopics,visibility
```

Expected: description + homepage as set, 8 topics, `"visibility": "PRIVATE"`
(the flip is the operator's — do NOT change visibility).

Note: private vulnerability reporting, secret scanning, push protection, and
CodeQL default-setup alerts are **public-repo-only** — they are on the
go-public checklist (Task 10), not here.

---

### Task 10: Full-history secrets scan + go-public checklist

**Files:**
- Create: `docs/go-public-checklist.md`

- [ ] **Step 1: Install and run gitleaks over all history**

```bash
brew install gitleaks
gitleaks git --redact --verbose .
```

Expected: `no leaks found`. If it reports findings:
- A hit inside `fixtures/malicious/**` or `fixtures/benign/**` that is part of
  a `SYNTHETIC FIXTURE` (fake key material invented for a test) is a false
  positive — verify the surrounding file has the synthetic header and the
  value matches nothing real, then record it in the PR description.
- **Any other hit: STOP.** Do not rewrite history, do not proceed to the PR —
  report the finding (redacted) to the operator and wait. (Global constraint:
  no history rewriting without operator sign-off.)

- [ ] **Step 2: Belt-and-braces grep for high-signal patterns**

```bash
git grep -I -n -E "(ghp_|gho_|github_pat_|sk-ant-|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----)" $(git rev-list --all) -- . 2>/dev/null | grep -v "fixtures/" | head -20
```

Expected: no output (fixture paths excluded; test keypairs generated at test
time never land in git — `fixtures/signing/` and `fixtures/signing-keys.json`
are gitignored). Any output: same STOP rule as Step 1.

- [ ] **Step 3: Write `docs/go-public-checklist.md`**

```markdown
# Go-public checklist (operator)

Pre-flight is done on the `oss-launch-prep` branch: LICENSE, SECURITY.md,
CODE_OF_CONDUCT.md, CONTRIBUTING.md, threat model, CodeQL workflow, issue
templates, README status/badges, repo description/homepage/topics, and a
clean full-history secrets scan (gitleaks + pattern grep). What remains
needs the repo to be PUBLIC, so it's yours, in order:

1. **Merge** `oss-launch-prep` into `main` and push.
2. **Flip visibility**: repo Settings → General → Danger Zone → Change
   visibility → Public. (Everything in git history becomes visible; the
   secrets scan covering all commits was a merge precondition.)
3. **Enable private vulnerability reporting** (public-only):
   `gh api -X PUT repos/git-agentic/pkg-registry/private-vulnerability-reporting`
   — SECURITY.md's reporting instructions depend on this.
4. **Enable secret scanning + push protection** (public-only): Settings →
   Code security → enable both.
5. **Confirm CodeQL ran**: Actions → `codeql` workflow green on main;
   Security → Code scanning shows results.
6. **Confirm the badges render** on the README (ci + codeql + license) and
   the license is detected on the repo sidebar as Apache-2.0.
7. **Verify the GitHub Action is consumable**: in a scratch public repo, add
   a workflow step `uses: git-agentic/pkg-registry@main` pointing at the
   root `action.yml`; confirm it resolves and runs observe-only
   (`fail-on: none`).
8. **Spot-check rendering**: README, SECURITY.md, CONTRIBUTING.md,
   sentinel-threat-model.md, and one issue template (open the new-issue
   chooser — blank issues should be disabled, security contact link shown).
9. **Link the repo from https://git-agentic.com/sentinel.**
10. Optional: create a `v0.1.0` tag/release once you're happy — not part of
    this launch.
```

- [ ] **Step 4: Commit**

```bash
git add docs/go-public-checklist.md
git commit -m "docs: operator go-public checklist; full-history secrets scan clean"
```

---

### Task 11: Final verification + PR

**Files:** none new

- [ ] **Step 1: Full build + test**

```bash
npm run build && npm test
```

Expected: build clean; tests green — 659 pass / 2 skip on darwin (661 total,
see CLAUDE.md). This proves the launch prep touched no source code.

- [ ] **Step 2: Confirm zero source diffs**

```bash
git diff main...HEAD --stat -- packages/ scripts/ fixtures/
```

Expected: empty output.

- [ ] **Step 3: Push and open the PR**

```bash
git push -u origin oss-launch-prep
gh pr create --title "OSS launch prep: community files, threat model, CodeQL, templates, checklist" \
  --body "$(cat <<'EOF'
Implements docs/superpowers/specs/2026-07-09-oss-launch-design.md.

- LICENSE (Apache-2.0), SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md
- sentinel-threat-model.md (synthesized from ARCHITECTURE.md + ADRs 0001-0038)
- CodeQL workflow, issue templates (bug / detection-gap / feature), blank issues off
- README: badges, Status section, homepage; stale test count unpinned
- .gitignore: .superpowers/
- Repo settings set via gh (description, homepage, topics) — visibility NOT flipped
- Full-history secrets scan: gitleaks + pattern grep, clean
- docs/go-public-checklist.md — the operator's launch-day steps

Zero source-code changes (verified: empty diff under packages/, scripts/, fixtures/).
The visibility flip is deliberately left to the operator via the checklist.
EOF
)"
```

Expected: PR URL printed. The operator reviews and merges (`--no-ff` locally per usual flow), then follows `docs/go-public-checklist.md`.

# OSS launch prep — design

**Date:** 2026-07-09
**Status:** Approved
**Goal:** Make `git-agentic/pkg-registry` (Sentinel) ready for public open-source
launch, modeled on the public state of `git-agentic/git.agentic`. Everything is
prepared and verified; the final visibility flip to PUBLIC is done by the
operator, guided by a checklist this work produces.

## Scope decisions (locked with the operator)

- **Repo name stays `pkg-registry`.** No rename; branding comes from the
  description, homepage, and README.
- **Homepage is `https://git-agentic.com/sentinel`.**
- **`docs/superpowers/` planning docs stay public.** They pair with the ADRs as
  an engineering log; no history rewriting.
- **No npm publishing in this launch.** Users build from source; publishing
  `@sentinel/*` (real scope, provenance, versioning) is a separate later project.
- **Agent does everything except the visibility flip.** Repo settings are set
  via `gh`; the operator flips PRIVATE → PUBLIC as the final act.

## Gap analysis vs `git-agentic/git.agentic` (public reference)

Reference has, this repo lacks: `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
`CONTRIBUTING.md`, a root threat-model doc, a CodeQL workflow, a repo
description + homepage, PUBLIC visibility. Hygiene gaps found: `.superpowers/`
untracked but not gitignored; README quickstart says "308 tests" (stale; 661 on
this host); repo description/homepage empty.

## 1. Community & legal files (repo root)

- **`LICENSE`** — Apache-2.0 full text. Copyright line: `Copyright 2026
  git-agentic`. (package.json already declares `Apache-2.0`; the reference repo
  is also Apache-2.0.)
- **`SECURITY.md`** —
  - Supported versions: pre-1.0, `main` only.
  - Reporting: GitHub **private vulnerability reporting** (Security tab →
    Report a vulnerability). No email address published.
  - Scope guidance specific to Sentinel: a sandbox escape, gate bypass,
    fail-open scoring path, or auth bypass **is** a vulnerability; "a rule
    missed my sample" / "package X should have been flagged" is a
    detection-gap issue (public issue template), not an advisory.
  - Note that malicious fixtures are synthetic, inert, scored-as-text, never
    executed (links the fixture safety rules).
- **`CODE_OF_CONDUCT.md`** — Contributor Covenant 2.1, unmodified apart from
  the enforcement contact (GitHub report-abuse / maintainer handle, no email).
- **`CONTRIBUTING.md`** —
  - Build/test/fixtures quickstart (`npm install && npm run build && npm test`,
    `npm run fixtures`, `npm run demo`), Node >= 22, test-count note pointing
    at CLAUDE.md as the source of truth.
  - **Fixture safety rules front and center**: never live malware; synthetic,
    inert, `SYNTHETIC FIXTURE` header, RFC 5737 IPs; scored as text, never
    executed.
  - How to add a detection rule / tune policy (mirrors CLAUDE.md "How to
    extend"); the non-negotiable invariants summarized with a pointer to
    CLAUDE.md/ARCHITECTURE.md.
  - ADR process: never edit an Accepted ADR to reverse it; supersede.
  - Issue triage labels (`needs-triage`, `needs-info`, `ready-for-agent`,
    `ready-for-human`, `wontfix`) with a pointer to `docs/agents/`.
  - PR expectations: definition of done = build clean, tests green, malicious
    fixture still blocked.

## 2. Threat model

**`sentinel-threat-model.md`** at the repo root (placement mirrors
`git.agentic-threat-model.md`). Produced with the `security-threat-model`
skill, **synthesized from ARCHITECTURE.md + the 38 ADRs — no new analysis**:

- Trust boundaries: npm upstream ↔ proxy; proxy ↔ installer; installer ↔
  sandboxed lifecycle scripts; control plane (approvals/violations/policy) ↔
  roles; operator trust material (signing keys, pinned provenance roots).
- Assets: developer credentials/env, the scoring verdict's integrity, policy
  signing keys, the private-namespace store, audit history.
- Attacker capabilities considered: malicious package author, compromised
  maintainer/release, name-squatter, network MITM (out of scope vs TLS),
  malicious packument (SSRF — closed by ADR-0036), resource exhaustion
  (ADR-0037), agent-with-token abuse (ADR-0024/0025 request-not-grant).
- Honest accepted limitations: heuristics are signal not proof; swallowed-denial
  telemetry evasion (containment unchanged, ADR-0023); Seatbelt/bwrap telemetry
  asymmetry (ADR-0038); LLM enrichment is advisory only; fail-open stances that
  are deliberate (tree rows on unresolvable packages, attestation fetch).

## 3. CI & GitHub hygiene

- **`.github/workflows/codeql.yml`** — CodeQL, `javascript-typescript`, on push
  + PR to `main` + weekly cron. Parity with the reference repo.
- **Issue templates** (`.github/ISSUE_TEMPLATE/`):
  - `bug_report.yml` — labels: `needs-triage`.
  - `detection-gap.yml` — Sentinel-specific: missed detection or false
    positive; asks for package name/version/integrity and expected vs actual
    verdict; labels: `needs-triage`.
  - `feature_request.yml` — labels: `needs-triage`.
  - `config.yml` — `blank_issues_enabled: false`; contact link routing
    security reports to private vulnerability reporting.
- **`.gitignore`** — add `.superpowers/`.

## 4. README freshness (surgical, no restructure)

- Fix the stale "308 tests" quickstart line (point at CLAUDE.md's count).
- Add a short **Status** section near the top: built through Phase 25
  (deny-by-default sandbox), what it is not yet — not production-hardened, no
  published npm packages (build from source), pre-1.0.
- Link the homepage `https://git-agentic.com/sentinel`.
- Badges: CI workflow status + Apache-2.0 license.

## 5. Repo settings via `gh` (everything except the flip)

- Description: "Agent-auditable security layer for npm — auditing proxy,
  deny-by-default install sandbox, provenance & signature verification, SBOM +
  signed attestations, MCP surface."
- Homepage: `https://git-agentic.com/sentinel`.
- Topics: `npm`, `supply-chain-security`, `security`, `sandbox`, `sbom`,
  `provenance`, `mcp`, `ai-agents`.
- **Not now (post-flip, on the checklist):** private vulnerability reporting
  (`gh api -X PUT repos/{owner}/{repo}/private-vulnerability-reporting` —
  public-repo-only, the call fails on a private repo), secret scanning + push
  protection, and CodeQL default-setup alerts — all features that only
  activate on public repos.

## 6. History hygiene + go-public checklist

- Full-history secrets scan: gitleaks over all commits (335 at design time),
  plus targeted grep for token/key patterns. **If anything is found: stop and
  decide with the operator — no history rewriting without sign-off.**
- Deliverable: **`docs/go-public-checklist.md`** — ordered operator actions at
  launch: flip visibility; enable private vulnerability reporting; confirm
  secret scanning + push protection activated;
  confirm CodeQL ran; verify the GitHub Action is usable from a public repo
  (`uses: git-agentic/pkg-registry@main` + `action.yml` path check); spot-check
  rendered README/SECURITY/threat model on github.com; optionally add the repo
  to the git-agentic.com/sentinel page.

## 7. Process & verification

- Branch `oss-launch-prep`, one reviewable PR; operator merges `--no-ff`
  locally per usual flow.
- Definition of done: `npm run build` clean; `npm test` green (661 on darwin
  per CLAUDE.md); gitleaks clean (or findings escalated); new YAML validated
  (actionlint or GitHub's parser via a draft push); `gh repo view` reads back
  the settings; **zero source-code changes** — docs, workflows, templates, and
  settings only.

## Explicitly out of scope

- Visibility flip (operator does it, via the checklist).
- npm publishing of `@sentinel/*`.
- Repo rename.
- History rewriting of any kind.
- Website/blog content (lives with git-agentic.com, not this repo).
- Any change to scoring, sandbox, proxy, or other source code.

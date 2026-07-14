# Security Policy

Sentinel is a security product — an auditing proxy, policy gate, and install
sandbox for the npm ecosystem. We treat reports against it accordingly.

## Supported versions

Sentinel is pre-1.0. Only the tip of `main` and the most recent published
prerelease (`@git-agentic/sentinel-*@alpha`) are supported;
there are no maintained release branches. Prereleases are snapshots of
`main` — fixes ship as the next prerelease, never as patches to an old one.

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

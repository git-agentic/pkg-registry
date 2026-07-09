# ADR-0016: macOS Seatbelt sandbox runner (ADR-0011 stage A, partial)

**Status:** Accepted (write-posture stance partially superseded by ADR-0038 — writes are now deny-by-default; the Seatbelt runner itself is unchanged)
**Date:** 2026-06-26
**Phase:** 3 (implements ADR-0011 Option A for macOS)

## Context
ADR-0011 stage B made capability an approved, recorded decision but did not constrain
execution. Stage A is runtime least-privilege: run lifecycle scripts in a sandbox whose
profile is generated from the package's approved capabilities.

## Decision
1. **macOS Seatbelt (`sandbox-exec`)** behind a `Sandbox` interface (Linux landlock/
   bubblewrap is a future impl). Verified empirically: file-read and network denies are
   enforced here.
2. **Allow-default + targeted-deny** profile (deny-by-default SIGABRTs on dyld).
3. **Enforced surface = filesystem reads + network egress**, each relaxed by an approved
   capability; children/native inherit the sandbox. Network is **all-or-nothing**
   (Seatbelt can't host-filter); per-host fidelity lives on the proxy.
4. **Fail closed off-darwin** — the runner refuses, never runs unsandboxed.
5. **DRY** the credential deny-list with `secret-exfil` via a shared `SENSITIVE_PATHS`.
6. **The violation report is inferred** (detected − approved), not kernel-observed (the
   unified log isn't reliably available), and best-effort (a swallowed EPERM produces no
   report). Enforcement is the guarantee; the report is opportunistic.

## Consequences
- The MVP is the enforcement primitive + `sentinel run-scripts` on one resolved package.
  Deferred: full `npm install --enforce` tree orchestration + npm-env replication; Linux;
  per-host script network / force-`HTTP_PROXY`; observe/dry-run; kernel-observed reports;
  write-confinement; proxy-approval fetch in `run-scripts`.
- The synthetic-malware fixtures remain scored-as-text and unexecuted; enforcement is
  tested with benign in-test probe packages asserting the protected-resource effect.
- **Enforced surface is sensitive FILE reads + network egress.** Environment-variable-borne
  secrets (`NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.) are NOT scrubbed — lifecycle scripts
  inherit `process.env`. Env-var scrubbing is out of scope (deferred); the audit engine's
  `secret-exfil` rule still detects env reads at audit time.

---

**Annotation (2026-06-30 — Phase 4):** The two deferred gaps noted above are now closed
by **ADR-0017** (sandbox env-var scrubbing and write-confinement). Env-var scrubbing is
fail-closed via `scrubEnv` + `ENV_ALLOWLIST`; credential env-vars can be approved with
`--approve env:NAME` (new `env` capability kind). Write-confinement adds `file-write*`
denies for credential paths (now `modes: ["read","write"]` in `SensitivePath`) and new
persistence-only targets (`LaunchAgents/Daemons`, shell rc, crontab spool, autostart).
The Accepted decision above is unchanged; this note records closure only.

# ADR-0017: Sandbox env-var scrubbing and write-confinement (Phase 4)

**Status:** Accepted
**Date:** 2026-06-30
**Phase:** 4 (closes the two enforcement gaps ADR-0016 explicitly deferred)

## Context

Phase 3 (ADR-0016) left two exfiltration/persistence holes open:

1. **Env-borne secrets** — lifecycle scripts inherit `process.env` wholesale. A malicious
   script can read `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc. without
   touching any file. The `file-read*` deny in the Seatbelt profile does nothing here.
   ADR-0016 noted this explicitly: "Env-var scrubbing is out of scope (deferred)."

2. **Unrestricted writes** — the allow-default profile leaves all writes open. A script can
   append to `~/.bashrc`/`~/.zshrc`, drop a `LaunchAgent`, overwrite `~/.ssh/authorized_keys`,
   or edit a crontab spool file. None of these are denied today.

Phase 4 closes both gaps. Per-host network filtering and kernel-observed denial capture
remain deferred (unchanged from ADR-0016).

## Decision

### D1 — Close both gaps in one phase

Env-scrub and write-confinement share the `SENSITIVE_PATHS` source, are darwin-testable
with the same benign sandbox-probe fixture, and together form a coherent "close exfil +
persistence" surface. Splitting them across phases would create a window where env scrubbing
exists without write protection and vice versa.

### D2 — Env scrubbing is allowlist-based (fail-closed)

`scrubEnv(sourceEnv, approvedEnv)` in `@sentinel/sandbox` passes only vars whose names
match `ENV_ALLOWLIST` **or** are explicitly named by an approved `env` capability. Every
unmatched var — including a novel-named credential not yet on any list — is dropped.

This is consistent with the project's fail-closed ethos (private namespaces fail-404,
off-darwin enforcement refuses) and with the threat model: the risk of over-passing (a
credential reaches the script) is graver than over-blocking (a script is missing a var it
would prefer to have).

**`ENV_ALLOWLIST` scope:** The allowlist was validated against a real `npm install`
lifecycle env dump. The **load-bearing** behavior is dropping operator-shell secrets:
`SSH_AUTH_SOCK`, `AWS_*`, `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `GITHUB_*`, etc.

The allowlist includes `npm_config_*`, `npm_package_*`, `npm_lifecycle_*`, `npm_node_*`
prefix groups for defensive completeness, but these are **forward-looking**: `sentinel
run-scripts` is invoked directly by the operator, NOT by npm, so npm does not inject
`npm_*` vars into the current `run-scripts` invocation. Those entries are deferred
insurance for the planned `sentinel install --enforce` path where npm-env replication
will matter.

**`NODE` vars are enumerated exactly** — not a `NODE*` prefix — to avoid inadvertently
passing `NODE_AUTH_TOKEN` (a registry auth token used by some npm toolchains). The
allowlist contains `NODE`, `NODE_ENV`, `NODE_PATH`, `NODE_NO_WARNINGS`, and
`NODE_OPTIONS` individually. Separately: modern npm does NOT leak registry credentials
into the `npm_config_` namespace (probed; confirmed absent in the env dump), so
`npm_config_registry` or `npm_config_//registry.npmjs.org/:_authToken` are not an
active concern for the current `run-scripts` path.

### D3 — Env passthrough via a new `env` capability kind

`CapabilityKind` gains `"env"`. `target` = the env var name (e.g. `NPM_TOKEN`); `"*"`
is the dynamic/uncomputable sentinel.

`scanForCapabilities` detects env-credential reads in lifecycle scripts (`process.env.X`,
`process.env["X"]`, destructured `const { X } = process.env` where `X` matches the
credential shape). These mirror the patterns the existing `secret-exfil` rule already
uses, keeping detection and enforcement no-drift.

`parseApprovals` accepts `env:<NAME>` — the same `--approve` UX as `filesystem` and
`network`. An approved `env` capability adds that var's name to the `scrubEnv` passlist
for that invocation. `unapprovedAtoms` already covers `env` atoms (the pipeline is
kind-generic), so a script failing after reaching for an unapproved `NPM_TOKEN` appears
in the inferred failure report with no extra code.

### D4 — Per-mode `SensitivePath` with persistence entries

`SensitivePath` gains `modes: ("read" | "write")[]`. This gives a single source of truth
with mode-aware consumption:

- **Credential paths** (`~/.ssh`, `~/.aws/credentials`, `~/.npmrc`, `~/.gnupg`,
  `~/.netrc`, `~/.git-credentials`, `~/.docker/config.json`, `~/.kube`, shell rc files,
  `/etc/passwd`, `/etc/shadow`) → `modes: ["read","write"]`. Both exfil (read deny) and
  tamper (write deny) are blocked.

- **Persistence-only paths** (new) → `modes: ["write"]`: `~/Library/LaunchAgents`,
  `~/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`,
  `/private/var/at/tabs` (crontab spool), `~/.config/autostart`. These have no
  `detectRe` (persistence-only) so `secret-exfil` ignores them — only the sandbox
  write denies apply.

`generateProfile` emits `(deny file-write* ...)` for each `modes.includes("write")`
entry not covered by an approved `filesystem` capability, alongside the existing
`(deny file-read* ...)` for read-mode entries. Same `pathCovers` and
`canonicalizeMacPath` helpers reused.

**Firmlink canonicalization is required for write denies too.** Probed: a deny on
`/tmp` does not match writes to `/private/tmp` (macOS firmlinks are transparent to
Seatbelt). `canonicalizeMacPath` must be applied to all deny paths — read and write.
Directory targets use `denyKind: "subpath"` to block file creation within, not just
the directory node itself.

### D5 — A `filesystem` approval relaxes both read and write

A `--approve filesystem:<path>` capability removes **both** the read and the write deny
for that path from the generated profile. The `filesystem` capability kind stays
mode-agnostic. Read/write sub-kinds (`filesystem:read:<path>`, `filesystem:write:<path>`)
are YAGNI and explicitly deferred — no production demand identified.

## Consequences

- **Enforced surface now covers** sensitive file reads + network egress (Phase 3) **plus**
  env-var secrets scrubbing + writes to credential and persistence paths (Phase 4).
- `scrubEnv` is pure and deterministic — same `(sourceEnv, approvedEnv)` inputs always
  produce the same output, unit-testable without a kernel on every platform.
- Profile generation remains pure and deterministic (same inputs → same SBPL profile),
  covering both read and write denies, all firmlink-canonicalized.
- Detected-but-unapproved `env` atoms surface in the inferred failure report (kind-generic
  pipeline, zero extra code). The honesty caveat is unchanged: the report is
  static-inferred and best-effort on loud failure; the hard guarantee is kernel enforcement.
- Deferred (unchanged from ADR-0016): full `npm install --enforce` tree orchestration +
  npm-env replication for the `npm_*` allowlist; Linux enforcement; per-host network
  filtering; kernel-observed denial capture; read/write filesystem sub-kinds.

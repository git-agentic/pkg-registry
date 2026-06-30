# ADR-0018: Cross-platform sandbox backends (bubblewrap on Linux)

**Status:** Accepted (Phase 5)
**Date:** 2026-06-30

## Context
Phases 3–4 enforce an approved capability manifest at install time on macOS via Seatbelt.
Off-darwin, `SeatbeltSandbox` throws (fail-closed) — so Linux, where most CI and agent
installs run, got *refusal*, not *enforcement*. We need the same least-privilege on Linux.

## Decision
Add a Linux enforcement backend using **bubblewrap (`bwrap`)** and select the backend by
platform via `createSandbox()` (darwin→Seatbelt, linux→Bubblewrap, else throw).

- **Why bubblewrap, not Landlock/seccomp.** Sentinel's model is *allow-default + deny
  specific paths*. Landlock is allow-list-only — it cannot deny a subpath of a granted
  hierarchy, so "allow `~` except `~/.ssh`" is inexpressible — and needs a native helper
  (no Node binding). bubblewrap replicates the existing model exactly: `--bind / /`
  (allow-default read+write), then mask each sensitive path. Probe-verified on Ubuntu 24.04.
- **Deny mapping (probe-confirmed).** `denyKind: "subpath"` → `--tmpfs <path>` (content
  masked, writes land on a throwaway tmpfs so persistence payloads do not survive);
  `denyKind: "literal"` → `--ro-bind /dev/null <path>` (reads return empty, writes EPERM).
  Both are robust to a nonexistent target and cover read **and** write, so the bwrap side
  does not need the read/write `modes` split the SBPL side uses. `--unshare-net` denies all
  network unless a `network` capability is approved (all-or-nothing, same as Seatbelt; per-
  host fidelity stays on the proxy). No firmlink canonicalization (Linux has no firmlinks).
- **Interface.** `Sandbox.run` now takes structured policy (`approved` + `homeDir`); each
  backend compiles its own profile (SBPL or bwrap argv) internally. The runner/CLI no longer
  know SBPL exists. Capability-coverage matching (`pathCovers`) is shared, so an approval
  cannot cancel a deny on one platform but not the other.
- **Platform-specific persistence paths.** `SENSITIVE_PATHS` entries carry an optional
  `platforms` tag; `sensitivePathsFor(platform)` filters. Credential + shell-rc paths are
  shared; LaunchAgents/LaunchDaemons/`/var/at/tabs` are darwin; systemd-user units
  (`~/.config/systemd/user`, `~/.local/share/systemd/user`) and XDG autostart
  (`~/.config/autostart`) are linux — all HOME-based. The system cron spool
  (`/var/spool/cron/crontabs`) is intentionally NOT bwrap-denied: it is root-owned
  (mode 1730) and OS-protected against unprivileged writes, and bwrap cannot create that
  root-owned mountpoint unprivileged — it would abort the sandbox with "Can't mkdir
  parents … Permission denied". This is the macOS↔Linux mechanism difference: Seatbelt is
  a path filter and needs no mountpoint; bwrap mounts and requires a creatable mountpoint.
  Each generator is pinned to a fixed platform (not `process.platform`) so it is
  deterministic regardless of the test host.

## Fail-closed
`BubblewrapSandbox` throws (never runs the script unsandboxed) when not on Linux, when
`bwrap` is absent, or when the kernel refuses user-namespace creation. On **Ubuntu 24.04**
unprivileged user namespaces are AppArmor-restricted by default
(`kernel.apparmor_restrict_unprivileged_userns=1`); CI sets it to `0` so the Linux
effect-tests can enforce. This is documented and load-bearing — verified empirically before
implementation.

## Consequences
- Linux installs get the same credential-read, network-egress, and persistence-write denial
  macOS already had. Effect-tests run in CI (Linux) and skip on the dev's Mac; the macOS
  effect-tests run on the Mac and skip in CI — each platform is verified somewhere.
- bwrap is an external dependency (must be installed) and needs unprivileged user namespaces
  enabled. Both are handled in CI; operators on locked-down hosts get a loud fail-closed error.

## Rejected
- **Landlock + seccomp** — wrong model fit (allow-list-only), native-helper burden, kernel-
  version churn (network rules need ABI v4 / kernel 6.7).
- **Stacking seccomp on bwrap "for depth"** — YAGNI; no in-scope threat needs syscall filtering.
- **Reusing the `profile: string` slot for bwrap argv** — leaky abstraction; backends own
  their own compilation.

Supersedes nothing; extends ADR-0016 (which deferred non-macOS enforcement) and ADR-0017
(which `SENSITIVE_PATHS.modes` come from).

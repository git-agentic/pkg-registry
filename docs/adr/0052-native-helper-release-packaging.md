# ADR-0052: Landlock helper release packaging — source-only, explicit opt-in build, honest advisory fallback

**Status:** Accepted
**Date:** 2026-07-13

Extends ADR-0044 (Landlock exec floor — from-source helper, fail-open
pre-checked detection). Supersedes nothing.

## Context

`v0.1.0-alpha.1` is Sentinel's first npm publication. Every package ships as a
built artifact — except one file that cannot be treated like compiled
JavaScript: the Linux Landlock helper (`packages/sandbox/native/landlock-exec.c`),
compiled by `npm run build` (`scripts/build-native.mjs`) into
`dist/landlock-exec`. In the monorepo that is fine — the operator builds on the
machine that runs it. A published npm tarball breaks that assumption three
ways:

1. A binary compiled on the packing machine (a CI runner, or a maintainer's
   laptop) is architecture- and libc-specific. Shipping a Linux x64 binary as
   `dist/landlock-exec` would silently present it as portable to arm64/musl
   hosts, where it would fail `--check` and fall back — at best dead weight, at
   worst a supply-chain-shaped artifact nobody can reproduce from the tarball.
2. Compiling at install time via a lifecycle script is a **posture violation**:
   Sentinel's entire premise is that install-time script execution is the
   attack surface. `build-native.mjs`'s own header records this constraint
   (deliberately a build step, never a postinstall hook), and CLAUDE.md pins
   it as a stack rule.
3. Downloading a prebuilt binary at install or first-run time would put an
   unauditable network fetch inside the trust boundary — worse than either.

ADR-0044 already designed for helper absence: detection is fail-open and
pre-checked (`landlock-exec --check` ABI probe, cached), and a missing or
non-working helper falls back to the Phase 29 advisory floor with a one-time
stderr notice, with filesystem/network/env containment and the `/dev/null`
exfil-tool carve-out unaffected.

## Decision

For `0.1.0-alpha.1`, `@git-agentic/sentinel-sandbox` ships the helper **as source only**,
with an explicit, operator-invoked build path and the documented advisory
fallback:

1. **The tarball never contains a compiled helper.** The `files` allowlist
   excludes `dist/landlock-exec` explicitly, and the release-hygiene test
   (`packages/core/test/package-contents.test.ts`) fails the suite if a
   compiled helper ever enters a packed tarball — so a Linux-built release
   pipeline cannot ship one accidentally.
2. **The tarball contains the source and the build script**:
   `native/landlock-exec.c` (self-contained, no kernel headers needed) and
   `scripts/build-native.mjs`. Both are first-party, reviewed files — the same
   from-source posture ADR-0044 chose over prebuilt distribution.
3. **Compilation is an explicit operator action, never a lifecycle script.**
   `node node_modules/@git-agentic/sentinel-sandbox/scripts/build-native.mjs` compiles the
   helper in place (Linux + `cc` only; a no-op elsewhere). There is no
   `postinstall`, no lazy runtime compile, and no network fetch. The package
   README documents the command and the trade-off.
4. **Default behavior on Linux is the advisory exec floor, stated honestly.**
   Fresh installs run without the helper: the pre-checked detection finds no
   binary and prints the one-time notice ("Landlock exec floor unavailable on
   this host — advisory floor active…"). Filesystem/network/env containment,
   the `SENSITIVE_EXECUTABLES` `/dev/null` carve-out, and violation telemetry
   are unaffected — the same fallback ADR-0044 shipped for Landlock-less
   kernels and no-`cc` hosts, now also the packaged-artifact default.
5. **macOS Seatbelt is untouched.** Seatbelt enforcement involves no native
   compilation; the darwin exec floor (ADR-0042) ships fully enforced.
6. **The missing-helper state is tested as shipped.** A Linux CI test copies
   the built `dist/` without the helper binary and asserts: scripts still run,
   the advisory notice prints exactly once per process, and containment is
   unchanged (`packages/sandbox/test/bubblewrap.test.ts`).

## Alternatives considered

- **Architecture-specific optional packages (`@git-agentic/sentinel-landlock-linux-x64`,
  … via `optionalDependencies` + `os`/`cpu`, the esbuild/swc pattern).** The
  strongest end-state — prebuilt, reproducible, no toolchain requirement — and
  the likely post-alpha direction. Rejected *for the alpha*: it multiplies the
  publish surface (per-arch packages, per-arch CI builders, provenance for
  each) before the first release has shipped at all, and a security product
  distributing opaque prebuilt binaries needs reproducible-build
  infrastructure (pinned toolchain, verifiable digests) that does not exist
  yet. Shipping it half-done would be worse than the honest fallback.
- **`postinstall` compilation.** Rejected outright — the posture violation
  named in Context; this is the exact class of behavior Sentinel flags in
  other packages (`install-scripts` rule).
- **Shipping the pack-machine's binary in the tarball.** Rejected — a Linux
  x64 artifact silently presented as portable, unreproducible from the
  tarball, and a standing temptation for the release pipeline to become a
  binary-injection point.
- **Blocking publication of `@git-agentic/sentinel-sandbox` (and its dependents).**
  Unnecessary — ADR-0044's fallback is a designed, tested, honest degradation,
  not a silent weakening: the notice states the exact residual (a dropped
  binary can exec but stays filesystem+network confined), and the enforced
  floor is one documented command away on hosts that want it.

## Consequences

- Linux exec-floor enforcement is **opt-in** for npm-installed alphas
  (explicit compile) instead of automatic — the price of refusing both
  lifecycle-script compilation and fake-portable binaries. Monorepo builds
  (`npm run build`) are unchanged.
- The threat model's "Landlock + from-source helper where available" caveat
  now has a distribution-channel dimension, recorded there (§3.9, §4).
- Publishing per-arch optional helper packages is the recorded follow-up for
  a later release, gated on reproducible-build infrastructure.

# Phase 26 — P1 resource & telemetry hardening (#7, #9) — design

**Date:** 2026-07-09
**Status:** Approved
**Closes:** [#7](https://github.com/git-agentic/pkg-registry/issues/7) (unbounded
tarball decompression DoS), [#9](https://github.com/git-agentic/pkg-registry/issues/9)
(forgeable confirmed-violation → quarantine)

Two independent P1 security fixes from the external review, co-designed here and
delivered as **two independent PRs** (one per issue), each with its own ADR.

---

## Part A — #7: Bounded tarball extraction

### Problem

`extractTarball` (`packages/core/src/extract.ts`) tallies `unpackedSize` and
`fileCount` but never bounds them. `SENTINEL_MAX_TARBALL_BYTES` (ADR-0037) caps
only *compressed* fetch bytes; decompression is unbounded. A small gzip/tar bomb
can exhaust memory/CPU, and diff mode extracts twice. Files over 2 MB aren't
buffered, but every under-2 MB text entry is retained in full in `files[]` with
no cap on entry count or total unpacked size.

### Design

**Caps (built-in defaults in core, overridable):**
- `maxUnpackedBytes` — default **1 GiB** (`1024 * 1024 * 1024`). Total
  decompressed bytes summed across all entries.
- `maxFileCount` — default **100000** entries.
- **No wall-time cap.** Byte + count caps bound CPU/memory deterministically;
  a wall-clock cap would introduce timing non-determinism (invariant #1) and
  flakiness. Documented as a deliberate non-goal.

Rationale for defaults: real npm packages are typically well under 500 MB
unpacked and ~50k files; a 256 MB compressed tarball at a high (≥4×)
compression ratio expands past 1 GiB, and a million-tiny-entry tar trips the
count cap. Defaults never hit a legitimate package.

**`extractTarball` signature** gains an options object:

```ts
extractTarball(
  tgz: Buffer,
  baseline?: Map<string, string>,
  opts?: { maxUnpackedBytes?: number; maxFileCount?: number },
): Promise<ExtractResult>
```

`ExtractResult` gains `truncated: boolean` (and an internal reason for the
finding text). Streaming is unchanged except: on each entry's `end`, after
`unpackedSize += bytes` / `fileCount += 1`, if either running total crosses its
cap, **abort the parse immediately** (stop feeding the sink / end the parser)
and resolve with `truncated: true` and whatever was gathered so far. Over-cap
**never throws** — throwing stays reserved for a genuinely malformed tar. This
bounds retained memory to ≤ the caps and stops CPU work at the boundary.

**`runAudit` → finding.** When the *current* tarball's extraction returns
`truncated`, `runAudit` synthesizes a **critical `resource-abuse` finding** —
the same synthesize-in-`runAudit` mechanism already used for the
`integrity-mismatch` critical finding, not a `Rule` (it needs extraction
metadata, not `AuditInput`). Critical severity ⇒ hard block under the default
policy. The finding is deterministic (depends only on bytes + caps, no
wall-clock). Uses a new finding category `resource` (the plan verifies whether
`Finding.category` is an open string or a union to extend, and wires the
default policy weight for it — critical must hard-block regardless).

**Diff mode.** Both baseline and current extractions receive the caps (so a
bomb baseline can't DoS either). Only the **current** tarball's truncation
emits the block finding — the baseline is a prior version already served; its
truncation just bounds work and yields a partial diff baseline.

**Proxy wiring.** `SENTINEL_MAX_UNPACKED_BYTES` and `SENTINEL_MAX_FILE_COUNT`
parsed once at startup via `parsePositiveInt` (fail-closed FATAL on malformed —
same posture as the other `SENTINEL_MAX_*` vars), threaded through server
options → `runAudit` input → `extractTarball`. Defaults live in core so the
offline CLI and GitHub Action are protected without any env config.

### ADR

New ADR extending ADR-0037's resource-robustness lineage (does not supersede it
— adds the decompression dimension the fetch caps didn't cover).

---

## Part B — #9: Sensing ≠ enforcement for violations

### Problem

`POST /-/violations` sets `quarantined` directly from client-supplied
`confidence` (`ViolationStore.record`: `quarantined: v.confidence ===
"confirmed"`), gated only by "was this integrity audited." A caller with an
`agent` token — or anyone in open-auth mode — can forge a `confirmed` report
for any audited integrity, revoke its approval, and block serving until an
operator clears it. Quarantine is sticky. ADR-0023's telemetry framing
disclosed this as an accepted fail-closed DoS; this hardens it.

### Design

**Decouple sensing from enforcement.** `ViolationStore.record()` no longer
derives `quarantined` from client `confidence`. It takes an injected boolean:

```ts
record(v: ViolationInput, opts?: { autoQuarantine?: boolean }, now?: string): ViolationRecord
```

A `confirmed` report is **always recorded** (telemetry, unchanged). It
**quarantines** only when `opts.autoQuarantine` is true. Approval revocation
(`approvals.remove`) stays gated behind actual quarantine, so with
auto-quarantine off there is no destructive side-effect at all. Sticky-quarantine
semantics are unchanged for records that *do* quarantine.

**The server computes the flag**, never the client:

```
autoQuarantine = autoQuarantineEnabled && authz.enabled && v.confidence === "confirmed"
```

- **Default (no `SENTINEL_AUTO_QUARANTINE`):** record-only. Closes the
  forged/anonymous-DoS hole entirely — no report can quarantine.
- **Opt-in:** `SENTINEL_AUTO_QUARANTINE=1` restores ADR-0023's fleet-wide
  auto-containment for `confirmed` reports, but **requires**
  `SENTINEL_AUTH_PUBKEY` — startup **FATALs** if the flag is set without auth
  (fail-closed, same posture as the other startup env parsing). So every
  auto-quarantine is attributable to a verified token; open mode can never
  auto-quarantine.

**No new role.** The existing `agent` role still gates `POST /-/violations`
(it's telemetry). The protection is that the *destructive* side-effect is now
opt-in + auth-gated, not that reporting is more restricted. The
`sentinel-script-shell` reporter is unchanged (it already sends its token when
`SENTINEL_AUTH_TOKEN` is set).

**Startup wiring.** `SENTINEL_AUTO_QUARANTINE` parsed once at startup —
**`"1"` = on, unset/anything-else = off**, matching the existing
`SENTINEL_ENFORCE="1"` convention. FATAL if on without `SENTINEL_AUTH_PUBKEY`.
Threaded into server options; the server passes the computed per-request flag
to `record()`.

### ADR

New ADR **supersedes ADR-0023** (never edit an Accepted ADR to reverse it):
"violation telemetry is sensing; quarantine is enforcement, opt-in and
auth-gated by default." ADR-0023's containment claims (a swallowed denial is
still contained) are unchanged — this is only about the *reporting→quarantine*
edge.

### Backward-compatibility

This changes default behavior: previously a `confirmed` report auto-quarantined.
Deployments relying on that must now set `SENTINEL_AUTO_QUARANTINE=1` (+ auth).
This is the intended safer default. Existing tests asserting auto-quarantine are
updated to either pass the flag or assert record-only.

---

## Testing

**#7:**
- `extractTarball` units: a synthetic tar exceeding `maxFileCount` → `truncated`,
  and a high-ratio gzip exceeding `maxUnpackedBytes` → `truncated` with retained
  memory bounded; a small benign tar → `truncated: false`, full files.
- `runAudit`: a truncated current extraction → a critical `resource-abuse`
  finding → BLOCK verdict; determinism (same input + caps ⇒ same finding).
- The benign fixtures still extract fully and score unchanged; the malicious
  fixture still blocks.

**#9:**
- `ViolationStore` unit: `confirmed` + `autoQuarantine: false` → recorded, not
  quarantined, approval **not** revoked; `+ autoQuarantine: true` → quarantined
  + revoked; sticky semantics preserved for quarantined records.
- Server e2e: default (no env) → a `confirmed` `POST /-/violations` records but
  does not quarantine (serve still allowed); `SENTINEL_AUTO_QUARANTINE=1` +
  auth → quarantines and 403s the serve.
- Startup: `SENTINEL_AUTO_QUARANTINE=1` without `SENTINEL_AUTH_PUBKEY` → FATAL.
- The malicious fixture still blocks (scoring path untouched).

## Definition of done

`npm run build` clean; `npm test` green with new tests; new `SENTINEL_MAX_*` /
`SENTINEL_AUTO_QUARANTINE` env vars documented in CLAUDE.md + ARCHITECTURE.md +
README; two ADRs added (one extending ADR-0037, one superseding ADR-0023);
malicious fixture still blocked. Two PRs, each closing its issue.

## Out of scope

- Server-verifiable violation evidence (the server can't re-run the sandbox;
  trust remains in the reporter's credential — noted in the #9 ADR).
- A dedicated `reporter` role (considered, not chosen — the opt-in + auth gate
  achieves the security goal without a 4th role).
- Wall-time extraction cap (byte + count caps suffice; timing non-determinism
  avoided).

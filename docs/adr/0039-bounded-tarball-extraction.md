# ADR-0039: Bounded tarball extraction — decompression-bomb DoS guard

Date: 2026-07-10
Status: Accepted

## Context

ADR-0037 bounded the *fetch* side of the pipeline — a byte-counting reader
caps how many **compressed** bytes `NpmUpstream` will pull off the wire for a
tarball (`SENTINEL_MAX_TARBALL_BYTES`) or a packument/attestation
(`SENTINEL_MAX_PACKUMENT_BYTES`). It did not bound what happens next: `runAudit`
decompresses and untars every fetched tarball into memory to extract text
files for the rule pipeline (`extractTarball` in `packages/core`). A small,
capped-size `.tgz` can still gzip-bomb into an unbounded number of unpacked
bytes or an unbounded number of entries, so the same external-audit finding
that prompted ADR-0037 (#7) flagged extraction itself as an unbounded-work
path: a malicious tarball within the compressed-byte cap could still exhaust
memory or wall-clock decompressing before a single rule ever runs.

## Decision

`extractTarball` (`packages/core/src/extract.ts`) takes two caps —
`maxUnpackedBytes` (default `DEFAULT_MAX_UNPACKED_BYTES`, 1 GiB) and
`maxFileCount` (default `DEFAULT_MAX_FILE_COUNT`, 100k) — and feeds the
compressed tarball into the `tar.Parser` in fixed-size slices (256 KiB),
yielding to the event loop between slices, rather than writing the whole
buffer at once. Each entry's decompressed bytes accumulate into a running
total and each file increments a running count; the moment either exceeds its
cap, extraction sets a `truncated` flag and halts feeding further slices —
decompression stops mid-stream rather than running the bomb to completion.
`extractTarball` never throws on a breach (throwing stays reserved for a
genuinely malformed tar); it returns `{ truncated: true, ... }` with whatever
files were captured before the cap.

`runAudit` (`packages/core/src/audit.ts`) checks `extracted.truncated` on the
tarball being scored and, if set, pushes a synthesized critical finding
(`ruleId: "resource-abuse"`, `category: "resource"`) onto the audit —
independent of the rule pipeline, the same way `integrity-mismatch` is
synthesized. Under the default policy a critical finding hard-blocks, so a
decompression bomb resolves to a clear `BLOCK` verdict, not a crash, a hang,
or an OOM.

There is deliberately **no wall-time cap** alongside the byte/count caps.
Bounding by unpacked bytes and file count is sufficient to stop a bomb, and it
keeps the audit's determinism invariant (#1) intact — a wall-clock cutoff
would make the same input capable of producing a different truncation point
(and therefore a different finding set) depending on host load and scheduling
jitter, which a byte/count cap cannot do.

Two new fail-closed, load-once-at-startup env vars follow the exact posture
of ADR-0037's four: `SENTINEL_MAX_UNPACKED_BYTES` and `SENTINEL_MAX_FILE_COUNT`,
parsed with the same `resolvePositiveInt` helper used for
`SENTINEL_MAX_TARBALL_BYTES` et al. — a malformed value is FATAL at proxy
startup, not a silently-ignored default. Unset, both use the `extractTarball`
defaults above.

## Alternatives considered

- **Wall-time cutoff on extraction**: rejected — see determinism argument
  above; also redundant once bytes and file count are both capped, since a
  bomb that isn't stopped by either cap isn't a bomb.
- **Cap only unpacked bytes, not file count**: rejected — a tarball of many
  tiny/empty entries can exhaust memory and CPU on `tar.Parser` entry
  bookkeeping without ever approaching a byte cap (e.g. hundreds of thousands
  of zero-length files).
- **Reject the tarball outright (throw) on breach**: rejected — throwing
  collapses "bomb" and "corrupt tar" into the same failure mode and loses the
  chance to surface a specific, gradeable finding; returning `truncated` lets
  `runAudit` synthesize a named, weighted finding through the existing
  scoring machinery instead of a bare error path.

## Consequences

- A decompression bomb — small on the wire, huge unpacked — now resolves to a
  critical `resource-abuse` finding and a `BLOCK` verdict instead of an
  unbounded-memory install-time hang.
- This ADR **extends** ADR-0037; it does not supersede it. ADR-0037's fetch
  caps remain the compressed-byte bound at the network boundary, and this
  ADR's caps are the corresponding unpacked-byte/file-count bound at the
  extraction boundary — both fail-closed, both load-once-at-startup env
  vars, same operator posture.
- Diff mode (`baselineTarball` set) extracts *two* tarballs — the baseline
  and the current — under the same caps, but `runAudit` only inspects the
  **current** tarball's `truncated` flag when deciding whether to synthesize
  `resource-abuse`. A truncated baseline extraction silently degrades the
  diff (fewer files available for the changed-file comparison) without
  itself blocking the install; only a bomb in the version actually being
  installed blocks.
- Scoring stays deterministic given a policy (invariant #1): same tarball
  bytes + same caps ⇒ same `truncated` outcome ⇒ same finding set, always.

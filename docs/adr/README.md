# Architecture Decision Records

This is the decision log for Sentinel. Each ADR captures one significant choice —
the context and forces, the options weighed, the trade-off, and the consequences —
so that future contributors (and future Claude sessions) understand *why* the system
is the way it is, not just *what* it does.

Format follows the project's `/architecture` skill template (Nygard/MADR-style).
The load-bearing decisions are also summarized as invariants in
[`CLAUDE.md`](../../CLAUDE.md) and described in design terms in
[`ARCHITECTURE.md`](../../ARCHITECTURE.md).

## Status legend

`Accepted` — decided and (for Phase 1) implemented · `Proposed` — agreed direction,
not yet built · `Superseded` / `Deprecated` — replaced; see the linked successor.

## Phase 1 — the auditing-proxy wedge (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0001](./0001-auditing-proxy-wedge.md) | Auditing proxy, not an npm replacement | Insert a transparent proxy; attach signal, don't own packages |
| [0002](./0002-deterministic-scoring-llm-enrichment.md) | Deterministic scoring; LLM enrichment only | Rules set the score; the LLM may only add context, never the verdict |
| [0003](./0003-sync-gate-async-enrich.md) | Sync gate / async enrich split | Cheap deterministic gate inline; everything slow or networked runs async |
| [0004](./0004-integrity-hash-cache-key.md) | Integrity-hash cache key | Key verdicts on the tarball SRI hash — content-addressed, never stale |
| [0005](./0005-transparent-packument-passthrough.md) | Transparent packument pass-through | Forward the upstream doc; rewrite only `dist.tarball` |
| [0006](./0006-stack-node-typescript-workspaces.md) | Stack: Node + TS + npm workspaces | Live in the runtime we audit; one shared `AuditReport` contract |
| [0007](./0007-client-integration-registry-redirection.md) | Integrate via registry redirection | Point `registry` at the proxy — covers all PMs + transitive deps |
| [0008](./0008-diff-audit-weighting.md) | Diff-audit weighting | Amplify findings in files changed by a release (the trojaned-update signal) |
| [0009](./0009-synthetic-inert-fixtures.md) | Synthetic, inert malware fixtures | Prove detection with safe, reproducible fixtures, not live malware |

## Phase 2 — policy & permissions (Proposed)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0010](./0010-private-namespace-override.md) | Private-namespace override | Private packages win public collisions — structurally kill dependency confusion |
| [0011](./0011-install-time-permission-manifest.md) | Install-time permission manifest | Declare + approve (then sandbox-enforce) fs/network/process capability before execution |
| [0012](./0012-per-enterprise-policy-as-signed-data.md) | Per-enterprise policy as signed data | Make `POLICY` a versioned, signed, per-customer document; verdicts carry a `policyHash` |

## Phase 3–5 — sandbox enforcement (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0016](./0016-macos-seatbelt-sandbox-runner.md) | Sandbox enforcement (Phase 3) | `@sentinel/sandbox` enforces approved capabilities on macOS via Seatbelt; defers non-macOS |
| [0017](./0017-sandbox-env-scrub-and-write-confinement.md) | Sandbox hardening (Phase 4) | Fail-closed env scrubbing + write-confinement; `SENSITIVE_PATHS.modes` split |
| [0018](./0018-cross-platform-sandbox-backends.md) | Cross-platform sandbox backends (Phase 5) | `createSandbox()` selects Seatbelt (darwin) or bubblewrap (linux); same model, same deny paths |

## Conventions

- One decision per record; number sequentially; never renumber.
- Don't edit an Accepted ADR to reverse it — write a new one and mark the old
  `Superseded by ADR-NNNN`.
- When a Phase 2 ADR is implemented, flip its status to `Accepted` and check off its
  Action Items.
- If a change touches a decision recorded here, update the relevant ADR (or add one)
  as part of the change — see the Definition of Done in `CLAUDE.md`.

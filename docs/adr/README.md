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

## Phase 2 — policy & permissions (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0010](./0010-private-namespace-override.md) | Private-namespace override | Private packages win public collisions — structurally kill dependency confusion |
| [0011](./0011-install-time-permission-manifest.md) | Install-time permission manifest | Declare + approve (then sandbox-enforce) fs/network/process capability before execution |
| [0012](./0012-per-enterprise-policy-as-signed-data.md) | Per-enterprise policy as signed data | Make `POLICY` a versioned, signed, per-customer document; verdicts carry a `policyHash` |
| [0013](./0013-approval-gate-via-block-and-capability-delta-trigger.md) | Approval gate via the block path (Phase 2.1) | Trigger approval on a `block` verdict + a capability-delta-vs-prior-approved change; the gate reuses the block machinery |
| [0014](./0014-score-time-policy-and-raw-bytes-signing.md) | Score-time policy + raw-bytes signing (Phase 2.2) | Apply the signed policy at score time; sign/verify over raw policy bytes (Ed25519), verdicts carry the `policyHash` |
| [0015](./0015-private-registry-publish-protocol.md) | Private-registry publish protocol (Phase 2.3) | Publish auth + fail-closed routing: claimed namespaces are served only from the private store, never public npm |

## Phase 3–5 — sandbox enforcement (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0016](./0016-macos-seatbelt-sandbox-runner.md) | Sandbox enforcement (Phase 3) | `@sentinel/sandbox` enforces approved capabilities on macOS via Seatbelt; defers non-macOS |
| [0017](./0017-sandbox-env-scrub-and-write-confinement.md) | Sandbox hardening (Phase 4) | Fail-closed env scrubbing + write-confinement; `SENSITIVE_PATHS.modes` split |
| [0018](./0018-cross-platform-sandbox-backends.md) | Cross-platform sandbox backends (Phase 5) | `createSandbox()` selects Seatbelt (darwin) or bubblewrap (linux); same model, same deny paths |

## Phase 6 — enforced install (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0019](./0019-enforced-install-script-shell.md) | Enforced install via script-shell interposition | `sentinel install --enforce` interposes via `npm_config_script_shell`; every lifecycle script runs under `createSandbox()` with credential-screened env |

## Phases 7–22 — the signal & agent-surface build-out (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0020](./0020-whole-tree-lockfile-audit.md) | Whole-tree lockfile audit (Phase 7) | `sentinel audit-tree` fans a lockfile through the proxy and rolls a policy-gated server-side aggregate |
| [0021](./0021-signature-provenance-verification.md) | Signature & provenance verification (Phase 8) | Offline ECDSA registry-signature check + a `provenance` rule; optional `requireSignature`/`requireProvenance` gates |
| [0022](./0022-provenance-deep-verify.md) | Provenance deep-verify (Phase 9) | Verify Sigstore attestation bundles against pinned trust material, bound to the actual served bytes; `provenanceIdentities` gate |
| [0023](./0023-runtime-violation-telemetry.md) | Runtime violation telemetry (Phase 10) | The enforcing sandbox becomes a sensor: infer a violation, report best-effort, quarantine via a serve-time overlay |
| [0024](./0024-agent-native-mcp-surface.md) | Agent-native MCP surface (Phase 11) | A thin stdio client exposing read tools + a request-not-grant approval-request tool; no auto-approve |
| [0025](./0025-control-plane-auth.md) | Control-plane auth (Phase 12) | Opt-in signed Ed25519 role tokens (operator/agent/publisher) gate the mutating routes; reads stay open |
| [0026](./0026-supply-chain-identity-heuristics.md) | Supply-chain identity heuristics (Phase 13) | Pure `typosquat` rule + a score-time `dependencyConfusion` gate against claimed namespaces; weighted, never a hard block alone |
| [0027](./0027-ecosystem-breadth-sbom.md) | Ecosystem breadth + SBOM (Phase 14) | Multi-format lockfile parsing (npm/yarn/pnpm), CycloneDX 1.6 export, and a lockfile-integrity cross-check |
| [0028](./0028-durable-history-observability.md) | Durable history + observability (Phase 15) | Opt-in `node:sqlite` write-through beside the hot cache; `/-/metrics`, `/-/history`, `/-/violations/timeline` |
| [0029](./0029-release-anomaly-signals.md) | Release-anomaly signals (Phase 16) | Maintainer-change / dormancy / new-package / capability-novelty findings from immutable packument data; weighted |
| [0030](./0030-ci-native-github-action.md) | CI-native GitHub Action (Phase 17) | A self-booting proxy runs the tree audit in CI; SBOM artifact + idempotent PR comment; `fail-on` gating |
| [0031](./0031-actionable-remediation.md) | Actionable remediation (Phase 18) | Pure `remediate()` per-finding fixes + waiver templates + a last-known-good `/-/explain` walk-back; advisory-only |
| [0032](./0032-signed-audit-attestations.md) | Signed audit attestations / VSA (Phase 19) | Operator-side in-toto/DSSE Ed25519 attestation over an audited tree; pure, fail-closed offline `verifyAttestation` |
| [0033](./0033-policy-authoring-impact-preview.md) | Policy authoring + impact preview (Phase 20) | Pure `lintPolicy` + a dry-run `/-/policy/preview` replay of stored audits under a candidate policy |
| [0034](./0034-known-advisory-detection.md) | Known-advisory detection (Phase 21) | Bundled static GHSA corpus + a `known-advisory` rule that critical-hard-blocks an exact `(name, version)` match |
| [0035](./0035-known-vulnerability-sca.md) | Known-vulnerability SCA (Phase 22) | Bundled static CVE corpus + a `known-vulnerability` rule matching semver ranges at the advisory's faithful severity |

## Phase 23 — network trust boundary (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0036](./0036-network-trust-boundary.md) | Network trust boundary | Pin outbound tarball fetches to the registry origin/allowlist; require a configured public base URL off loopback |

## Phase 24 — resource robustness (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0037](./0037-resource-robustness.md) | Resource robustness | Audit-tree dedupe + cap, streamed byte caps, request coalescing, opt-in token-bucket rate limiting |

## Phase 25 — sandbox default-deny (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0038](./0038-sandbox-default-deny.md) | Sandbox default-deny (writes + reads) | Writes deny-by-default with a fixed floor + Grant re-allow (Slice 1); `$HOME` reads deny-by-default with a read-allow list for the node prefix/project root/caches (Slice 2) — both slices landed |

## Phases 26–27 — external-review hardening (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0039](./0039-bounded-tarball-extraction.md) | Bounded tarball extraction (Phase 26 Part A) | Cap unpacked bytes + file count at the gunzip boundary; a truncated current tarball is a critical `resource-abuse` finding |
| [0040](./0040-violation-sensing-vs-enforcement.md) | Violation sensing ≠ enforcement (Phase 26 Part B) | Quarantine becomes a server decision, opt-in via `SENTINEL_AUTO_QUARANTINE=1` + auth; recording stays open — closes the forged-violation DoS path |
| [0041](./0041-review-hardening.md) | Review hardening (Phase 27) | SHA-pin all third-party Actions; surface the >2 MB/non-text scan blind spot as `unscanned-content`; require a SLSA v1 predicate for `provenance: verified` |

## Phases 28–29 + Landlock — exec enforcement (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0042](./0042-exec-deny-by-default-darwin.md) | Exec deny-by-default on macOS (Phase 28) | Seatbelt denies `process-exec*` except a fixed floor + `process:` Grants, with a `SENSITIVE_EXECUTABLES` carve-out (curl, nc, …) |
| [0043](./0043-linux-exec-carveout-advisory-floor.md) | Linux exec carve-out, advisory floor (Phase 29) | bwrap masks exfil-tool literals with `/dev/null` binds; no bwrap `noexec` primitive exists, so the floor stays advisory |
| [0044](./0044-landlock-linux-exec-floor.md) | Landlock Linux exec floor | A from-source `landlock-exec` helper enforces the exec floor where kernel + toolchain allow; fail-open pre-checked detection, advisory fallback otherwise |

## Phases 30–32 — registry evolution (Accepted, implemented)

Design bundle for the proxy → first-class registry evolution
([roadmap](../product/registry-roadmap.md), wayfinder map
[#33](https://github.com/git-agentic/pkg-registry/issues/33)). Phase 30 is the
first shipped slice; Phases 31 and 32 complete claiming and retraction.

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0045](./0045-registry-write-path-resolution-merge.md) | Registry write path & deterministic resolution merge (Phase 30) | Name-level partition (policy → claim → mirror, first match); publish requires a claim; `publishGate` policy data; sync fail-closed gate, p50 ≤ 1 s / p99 ≤ 15 s |
| [0046](./0046-verified-namespace-claiming.md) | Verified namespace claiming (Phase 31) | Offline signed claim corpus; DNS TXT constitutive, OIDC = trusted publishing only; 12-month renewal, freeze-not-fallthrough; 30-day timelocked transfers/disputes; three-tier grandfathering |
| [0047](./0047-time-locked-retraction.md) | Time-locked retraction (Phase 32) | Retract only while age < 72 h AND downloads < 1,000 (policy data); tombstones + spent identifiers, history retained; two-speed advisory emission; default serve-time quarantine overlay |

## Phase 33 — registry compatibility (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0048](./0048-migration-compatibility-surface.md) | Migration & compatibility surface (Phase 33) | Small MUST-implement route contract (unpublish = retraction UI); fail-closed escape hatch with acknowledgment + revert manifest, retention + export; derived source class, integrity-preserving imports |

## Phase 34 — native-payload-loader detection (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0049](./0049-native-payload-loader-detection.md) | Native-payload-loader detection | Raw-byte magic classification (`content-mismatch`) + a dataflow-correlated `native-payload-loader` rule critically flag a disguised packaged-payload materialization-and-execution chain, independent of lifecycle scripts |

## Phase 35 — release-cooldown overlay (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0050](./0050-release-cooldown-overlay.md) | Release-cooldown overlay | Policy-data `releaseCooldown` (`hours` + `exempt` globs) holds freshly-published versions via a serve-time proxy overlay (no core wall-clock, cached score untouched); per-origin publish-time source; fail-closed on missing/unparseable time; overlaid across the tarball gate, `/-/audit`, `/-/explain`, `/-/audit-tree`, `/-/manifest` |

## Phase 36 — sandboxed exec (Accepted, implemented)

| ADR | Title | Decision in one line |
|-----|-------|----------------------|
| [0051](./0051-sandboxed-exec.md) | Sandboxed `sentinel exec` | `Sandbox.runArgv` (no-shell, execFile-style) + `sentinel exec -- <cmd>` reuse the approved-capability model, scrubbed env, and violation telemetry to contain Sentinel-mediated command execution; scoped to explicit invocations only — raw `require()`/`npx` outside it stay uncontained, defense-in-depth behind the ADR-0049 registry gate |
| [0052](./0052-native-helper-release-packaging.md) | Landlock helper release packaging | The published `@agentic-sentinel/sandbox` ships the helper as source only (`native/landlock-exec.c` + `build-native.mjs`) — never a prebuilt binary, never a `postinstall` compile; fresh Linux installs run the documented advisory exec floor with a one-time notice until the operator explicitly compiles the helper; enforced by the package-contents test and a missing-helper CI test |

## Conventions

- One decision per record; number sequentially; never renumber.
- Don't edit an Accepted ADR to reverse it — write a new one and mark the old
  `Superseded by ADR-NNNN`.
- When a Phase 2 ADR is implemented, flip its status to `Accepted` and check off its
  Action Items.
- If a change touches a decision recorded here, update the relevant ADR (or add one)
  as part of the change — see the Definition of Done in `CLAUDE.md`.

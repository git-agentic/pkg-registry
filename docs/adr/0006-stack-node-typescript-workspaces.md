# ADR-0006: Stack — Node + TypeScript on npm workspaces

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng
**Phase:** 1

## Context

We are building tooling for the npm ecosystem: parse `package.json`, resolve
semver, read tarballs, mirror the registry HTTP API, and ship a CLI as an npm
package. The team is small and the MVP timeline is short. The stack choice should
minimize impedance with the artifacts we audit and keep the shared `AuditReport`
contract honest across the proxy, the CLI, and the engine.

## Decision

Node + TypeScript, organized as an **npm-workspaces monorepo** with three packages:
`@sentinel/core` (engine — no I/O), `@sentinel/proxy` (Express server), and
`@sentinel/cli`. Express 5 for the proxy; `tar` 7 + built-in `zlib`/`fetch` for
extraction and upstream calls; `commander` 15 for the CLI; `node:test` + `tsx` for
tests. Developed against **Node 24 (Active LTS, June 2026)**; Node 22 (Maintenance
LTS) supported via `engines.node >=22`. TypeScript `NodeNext` ESM throughout, with
project references so `core` builds before `proxy`/`cli`.

## Options Considered

### Option A: Node + TypeScript + npm workspaces (chosen)
| Dimension | Assessment |
|-----------|------------|
| Ecosystem fit | Native — same runtime/tooling as what we audit |
| Team familiarity | High |
| Shared types | First-class (one `AuditReport` across packages) |
| Extra tooling | None (workspaces are built into npm) |

**Pros:** We parse and resolve packages exactly as npm does; the CLI ships natively;
types make the cross-package contract the source of truth; zero extra monorepo
tooling.
**Cons:** Static analysis in regex/light-AST is less rigorous than a heavyweight
analyzer; Node's single-threaded model means CPU-heavy audits need worker offload
at scale.

### Option B: Go (or Rust) services + TS only for the CLI
**Pros:** Faster CPU-bound scanning; easy static binaries; strong concurrency.
**Cons:** Two languages and two toolchains; we'd reimplement npm semantics
(semver, packument quirks) away from the reference ecosystem; slower iteration for a
small team. Reconsider for a high-throughput scanning worker later, not for the MVP.

### Option C: Heavier monorepo tooling (Nx/Turborepo/pnpm)
**Pros:** Better caching and task orchestration at scale.
**Cons:** Added config and concepts for three packages; npm workspaces + tsc project
references already cover build ordering. Premature.

## Trade-off Analysis

The dominant force is **ecosystem proximity**: an npm security tool benefits
enormously from living in the runtime it secures (same semver, same tarball format,
same `package.json` semantics), and ships its CLI without a cross-compile story. We
accept that raw scanning throughput is not Node's strength; the architecture already
isolates scanning in the pure `core` engine, so a future hot-path rewrite (Go/Rust
worker behind the same `AuditReport` contract) is possible without touching the
proxy or CLI.

## Consequences

- **Easier:** fast iteration; one type system end-to-end; native CLI distribution;
  deterministic tests with no build step (`tsx`).
- **Harder:** CPU-bound scanning at fleet scale will need worker threads or an
  out-of-process scanner; we live with regex/light-AST fidelity for now.
- **Revisit:** if scanning throughput becomes the bottleneck, extract `core` behind
  a service boundary and consider a compiled implementation — the contract makes
  this swappable.

## Action Items
1. [x] Workspaces: `core` (no I/O) → `proxy` + `cli` via tsc project references.
2. [x] Pin to current latest majors; `engines.node >=22`; CI matrix on 22 + 24.
3. [ ] Benchmark scan throughput; decide if/when a worker-thread pool is needed.

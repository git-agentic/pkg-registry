# ADR-0011: Install-time permission manifest with human/agent approval

**Status:** Accepted (stage B) — superseded options A/C deferred

> **Stage A (partial, 2026-06-26, ADR-0016):** a macOS Seatbelt runner now ENFORCES the
> approved capability set at install time (`sentinel run-scripts`). Linux + full
> `npm install --enforce` orchestration remain deferred.

**Date:** 2026-06-24
**Deciders:** Founder/Eng, Security lead, Design partner (enterprise)
**Phase:** 2

## Context

Even with a good audit verdict (Phase 1), `npm install` still grants every package's
lifecycle scripts unrestricted ambient authority: full filesystem, network, and
process access, executed silently. The audit *scores* risk; it does not *constrain*
capability. The next leverage point is to make capability **explicit and
approved** before execution — a per-package permission manifest (filesystem /
network / memory/process) that a human or an orchestrating agent must approve, so an
unexpected capability (a `postinstall` that suddenly wants the network) becomes a
prompt, not a silent breach.

## Decision

Define a declarative **permission manifest** describing the capabilities a package
needs at install/run time (e.g. `filesystem: [paths]`, `network: [hosts]`,
`process: spawn?`, `memory/native: addon?`). Sentinel derives a *requested*
capability set from static analysis (which it already computes for scoring) and
reconciles it against any declared manifest. On a delta — or on any package
requesting elevated capability — it **prompts for approval**: a human via the
dashboard/CLI, or an orchestrating agent via a structured approval API, with the
audit findings attached. Approvals are recorded per `(name, version, integrity)` so
they are stable and revocable. Enforcement strength is staged (see options).

## Options Considered

### Option A: Declare + approve, enforced by a sandboxed install runner (chosen target)
| Dimension | Assessment |
|-----------|------------|
| Security strength | High — capabilities actually constrained at runtime |
| Implementation cost | High — sandbox (container/VM/seccomp) for script execution |
| UX | Prompt only on delta/elevation |

**Pros:** Real least-privilege at the moment of execution; turns silent capability
into an explicit, auditable decision; agent-approvable for autonomous pipelines.
**Cons:** Requires a sandboxed execution environment for lifecycle scripts
(containers/seccomp/VM); cross-platform sandboxing is hard; performance overhead.

### Option B: Declare + approve, advisory only (no runtime enforcement)
**Pros:** Much cheaper; ship the manifest + approval UX and prompting first.
**Cons:** Approval is informational — a malicious script can still do anything once
it runs. Good as a *phase* toward Option A, not the end state.

### Option C: Block all install scripts by default (`--ignore-scripts`-style)
**Pros:** Simple, strong default; many packages don't need scripts.
**Cons:** Breaks legitimate native modules and build steps; blunt (no notion of
*which* capability); pushes users to disable Sentinel. Useful as an
allowlist-backed default, not a complete answer.

## Trade-off Analysis

The end-state value is **runtime least-privilege** (Option A), but the cost is a
sandboxed runner. We therefore stage it: ship the manifest schema, the
static-analysis-derived requested-capability set, and the human/agent approval flow
first (Option B's UX) — which already converts silent capability into an explicit,
recorded decision — then add sandboxed enforcement (Option A) so approvals become
actually binding. Option C's "deny scripts by default, allowlist exceptions" is a
sensible default policy layered on top once enforcement exists. This sequencing
delivers visible value early without locking us out of real enforcement.

## Consequences

- **Easier:** capability becomes explicit, recorded, and revocable; unexpected
  capability requests surface as prompts; autonomous agents get a structured
  approval API with findings attached.
- **Harder:** real enforcement needs a cross-platform sandbox for script execution;
  manifest authoring/derivation and approval state add product surface; risk of
  prompt fatigue if we prompt on more than deltas/elevation.
- **Revisit:** sandbox technology choice (container vs. seccomp/landlock vs.
  microVM); default policy (deny-scripts + allowlist) once enforcement lands;
  integration with the Phase 1 verdict (a `block` should pre-empt the prompt).

## Action Items
1. [ ] Permission manifest schema (filesystem / network / process / native).
2. [ ] Derive requested capabilities from existing static analysis; diff vs. declared.
3. [ ] Human approval (dashboard/CLI) + structured agent approval API; record per `(name,version,integrity)`.
4. [ ] Prototype a sandboxed install runner to make approvals enforceable.
5. [ ] Define default policy (deny-scripts + allowlist) layered on enforcement.

# ADR-0009: Test detection with synthetic, inert malware fixtures

**Status:** Accepted
**Date:** 2026-06-24
**Deciders:** Founder/Eng, Security lead
**Phase:** 1

## Context

A detection engine is only credible if there is a hard, repeatable test that it
catches malware. That requires malicious test inputs. But shipping real, live
malicious packages in the repo is dangerous (a contributor's machine could execute
a `postinstall`), often legally/operationally fraught, and **not even reproducible**:
the canonical historical sample, `flatmap-stream@0.1.1`, was unpublished from npm
after the event-stream incident (only a `0.0.1-security` placeholder remains), so it
can't be fetched at all.

## Decision

Detection is proven against **synthetic, inert fixtures** that reproduce the
*patterns* of real attacks. The malicious fixture (`color-stream`) models the
event-stream / ua-parser-js shape: a clean `1.4.0` and a trojaned `1.4.1` that adds
a `postinstall` harvesting env secrets and `~/.npmrc`, decoding an obfuscated base64
blob, `eval`-ing it, and exfiltrating over HTTPS. Safety rules for any malicious
fixture: never executed (scored as text only), carries a `SYNTHETIC FIXTURE`
header, and uses RFC 5737 documentation IPs (`198.51.100.0/24`, `203.0.113.0/24`)
that route nowhere. Tests stay hermetic via `LocalFixtureUpstream` and never hit
live npm. We additionally spot-check the engine against the *live* registry
manually (e.g. `is-odd` → allow, `esbuild` → flags its network postinstall) but do
not depend on the network in `npm test`.

## Options Considered

### Option A: Synthetic inert fixtures (chosen)
**Pros:** Safe on any machine; fully reproducible and hermetic; we control the exact
patterns and can target each rule; no legal/operational handling of live malware.
**Cons:** Synthetic samples could be unrealistically easy if authored carelessly —
they must mirror real techniques, not strawmen; they don't prove recall against
novel obfuscation in the wild.

### Option B: Vendor real known-malicious tarballs into the repo
**Pros:** Maximally "real."
**Cons:** Execution risk for contributors; storage/legal concerns; the key
historical samples are unpublished and unfetchable; couples tests to artifacts we
can't safely host. Rejected.

### Option C: Pull live samples from npm at test time
**Pros:** Real and current.
**Cons:** Non-hermetic (network-dependent, flaky CI), and the best samples are gone
from npm anyway. Reserved for *manual* validation only, never the test gate. Rejected
as the suite's basis.

## Trade-off Analysis

The core tension is **realism vs. safety/reproducibility**. Synthetic-but-faithful
fixtures give us a deterministic, machine-safe gate that asserts each rule fires on
the real attack signature, which is exactly what a regression suite needs. The
realism gap (novel in-the-wild obfuscation) is addressed out-of-band via manual
live-registry spot checks and, later, an enrichment-driven "candidate finding → rule"
loop (ADR-0002) — not by endangering the repo.

## Consequences

- **Easier:** safe contribution; deterministic CI; per-rule targeted coverage; the
  "malware is blocked" assertion is a hard gate (`npm test`).
- **Harder:** fixture authors must keep samples faithful to real techniques; we need
  a separate, non-gating process for live-sample validation.
- **Revisit:** maintain a private, sandboxed corpus of real samples for periodic
  recall measurement, isolated from the public repo and the test gate.

## Action Items
1. [x] `color-stream` clean/trojaned fixtures; RFC 5737 IPs; `SYNTHETIC FIXTURE` header.
2. [x] Hermetic tests via `LocalFixtureUpstream`; malicious fixture asserted `block`.
3. [ ] Stand up a private sandboxed real-sample corpus for offline recall metrics.

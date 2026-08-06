# ADR-0054: Obfuscation findings require a dynamic code-execution sink

**Status:** Accepted
**Date:** 2026-08-06
**Amends:** the Phase 1 `obfuscation` rule semantics in `ARCHITECTURE.md` §4.1

## Context

The original `obfuscation` rule treated each of these as independent evidence:
`eval`, the `Function` constructor, base64 decoding, `unescape`, long encoded
strings, `\xNN` runs, and character-code operations. That conflated three
different facts:

1. data is encoded or transcoded;
2. code is generated dynamically; and
3. concealed code is executed.

Only the third is evidence of the behavior this rule is named for. npm packages
legitimately ship encoded WASM/data assets, minified bundles, compatibility
transcoders, and runtime glue. Those shapes are not evidence of obfuscation on
their own.

The overly broad matcher also used `\beval\s*\(`, which matched any property
method named `eval`. In `@emnapi/core@1.9.2`, `g.eval(v8Script.value)` implements
a WebAssembly/N-API runtime operation; it is not JavaScript's direct evaluator.
The same package contains readable `new Function(...)` glue for constructing a
named wrapper. Sentinel emitted repeated high findings for both constructs
across the package's generated bundle formats. A package that bundled emnapi,
such as `@tailwindcss/oxide-wasm32-wasi`, inherited those findings for its
vendored copies.

ADR-0053 bounded repeated penalties but intentionally did not change detection
semantics. A cold calibration at its `a65ab42` baseline still had 70 production-
tree blocks involving `obfuscation`. Further arithmetic suppression would hide
the attribution error rather than correct it.

## Decision

The `obfuscation` rule reports evidence only when the source contains a dynamic
code-loading or execution sink:

- **JavaScript `eval(...)`** remains `high`, both as a direct identifier call and
  through an explicit standard global object (`globalThis`, Node's `global`, or
  browser `window`/`self`). An arbitrary method/property named `eval` (for
  example `runtime.eval(...)`) is excluded because its semantics are defined by
  that object, not the language evaluator.
- **A computed `require(...)` target** produced through the existing decoded or
  opaque-call shapes remains `high`.
- **The `Function` constructor** is `high` only when its source is decoded
  inline or comes from a locally assigned `atob(...)` / base64
  `Buffer.from(...)` result. A readable constructor body or runtime wrapper is
  dynamic code generation, but not concealed code.

These patterns are not `obfuscation` findings without such a sink:

- minification or generated bundles;
- correctly declared WASM/native/binary assets;
- a long base64/hex string;
- base64 decoding, `atob`, `unescape`, or character-code conversion used as
  data transcoding;
- `\xNN` data runs; or
- readable `Function`-constructor runtime glue.

This is a rule-semantics change, not a scoring-policy change. The rule remains a
pure deterministic `(AuditInput) => Finding[]` function and still constructs
every finding through `mkFinding()`. `DEFAULT_POLICY`, thresholds, severity
weights, the per-rule cap, and the pre-registered calibration criteria are
unchanged.

## Why this does not trade attack coverage for a target number

The removed primitives establish encoding or code generation, not concealed
code execution. Sentinel continues to flag the execution paths: direct or
explicitly-global eval, decoded `Function` source, and computed decoded
`require`. The committed
synthetic malicious release decodes a base64 stage and passes it to direct
`eval`; it therefore retains its high obfuscation finding and remains blocked at
score 0. Native packaged-payload materialization and execution also remains
covered independently by the dataflow-correlated `native-payload-loader` rule
(ADR-0049), including correctly declared payloads and content mismatches.

If future evidence shows a dangerous shape that does not reach one of these
sinks, add a correlation that describes that behavior. Do not restore a
standalone "encoded/minified data is obfuscation" penalty.

## Consequences

- Cold direct audits after this change produce no `obfuscation` findings for
  `@emnapi/core@1.9.2` (score 84, `allow`) or
  `@tailwindcss/oxide-wasm32-wasi@4.1.16` (score 80, `allow`). Other independent
  rule findings account for the remaining deductions.
- Finding messages and remediation now describe concealed dynamic execution,
  not "minified beyond normal" source.
- The local decoded-variable correlation is intentionally narrow and
  deterministic. It recognizes direct assignments from `atob` and base64
  `Buffer.from`; it is not represented as full JavaScript dataflow analysis.
- The complete four-tree calibration must be rerun cold in the consuming repo;
  these package probes validate the named false-positive class but do not
  substitute for that registered measurement.

## Rejected alternatives

### Lower weights or move thresholds

Rejected. Those are policy choices and would make the number smaller without
fixing the false attribution.

### Lower the per-rule cap again

Rejected. ADR-0053 already bounds repetition while retaining breadth of
evidence. Tightening it for this case would suppress every rule instance rather
than distinguish data assets from concealed code execution.

### Package or path allowlists

Rejected. The decision is based on behavior and applies equally to first-party,
vendored, scoped, and unscoped packages. No package name, publisher, filename,
or known hash changes the result.

# @sentinel/core

The Sentinel audit engine: deterministic heuristic rules, scoring, the audit
data model, multi-format lockfile parsing (npm/yarn/pnpm), CycloneDX 1.6 SBOM
export, signed policy and attestation primitives, and a pluggable LLM adapter
that can only ever *enrich* — never set — a score.

> **Alpha.** This is a pre-1.0 preview (`0.1.0-alpha.1`). APIs may change
> without notice. Not production-ready.

```bash
npm install @sentinel/core@alpha
```

```ts
import { runAudit, score, DEFAULT_POLICY } from "@sentinel/core";
```

The engine is fully offline and deterministic: same input + same policy ⇒ same
score, always. See the [Sentinel repository](https://github.com/git-agentic/pkg-registry)
for the full documentation, architecture, and threat model.

## License

Apache-2.0

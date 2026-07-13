# @sentinel/cli

The Sentinel CLI: pre-install audit verdicts (`sentinel audit`), whole-tree
lockfile audits with SBOM export (`sentinel audit-tree`), registry-redirected
installs (`sentinel install`, `sentinel npx`), sandbox-enforced installs
(`--enforce`), sandboxed one-shot commands (`sentinel exec`), policy
authoring/signing, and signed audit attestations.

> **Alpha.** This is a pre-1.0 preview (`0.1.0-alpha.1`). APIs may change
> without notice. Not production-ready.

```bash
npm install -g @sentinel/cli@alpha

sentinel --version
sentinel audit is-odd 3.0.1        # requires a running @sentinel/proxy
sentinel audit-tree package-lock.json
```

Most commands talk to a running [`@sentinel/proxy`](https://www.npmjs.com/package/@sentinel/proxy)
(default `http://localhost:4873`, override with `SENTINEL_PROXY` or `-p`).
See the [Sentinel repository](https://github.com/git-agentic/pkg-registry)
for the full command reference.

## License

Apache-2.0

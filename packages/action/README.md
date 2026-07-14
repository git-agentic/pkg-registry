# @agentic-sentinel/action

`sentinel-ci`: a self-contained CI runner for GitHub Actions. It boots the
Sentinel proxy in-process against real npm, audits your lockfile, writes a
CycloneDX SBOM, emits GitHub-native outputs/annotations, and renders an
idempotent PR comment body — no separately-running proxy needed.

> **Alpha.** This is a pre-1.0 preview (`0.1.0-alpha.1`). APIs may change
> without notice. Not production-ready.

```bash
npm install @agentic-sentinel/action@alpha
```

This package is the engine behind the composite GitHub Action defined at the
root of the [Sentinel repository](https://github.com/git-agentic/pkg-registry)
(`action.yml`). It is driven by `INPUT_*` environment variables
(`INPUT_LOCKFILE`, `INPUT_POLICY`, `INPUT_SBOM_PATH`, `INPUT_FAIL_ON`,
`INPUT_OMIT_DEV`, `INPUT_WORKING_DIRECTORY`) matching the action's inputs.

## License

Apache-2.0

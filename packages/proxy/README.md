# @agentic-sentinel/proxy

The Sentinel registry proxy: an Express server that transparently serves npm
packages while intercepting and auditing every tarball before install-time
code can run — plus an authoritative native publish path (`npm publish`
against Sentinel), verified namespace claims, time-locked retraction, and the
npm compatibility surface (packuments, dist-tags, unpublish-as-retraction).

> **Alpha.** This is a pre-1.0 preview (`0.1.0-alpha.1`). APIs may change
> without notice. Not production-ready.

```bash
npm install -g @agentic-sentinel/proxy@alpha
sentinel-proxy            # starts the proxy on :4873
```

Point any npm/pnpm/yarn/bun client at it:

```bash
npm install --registry http://localhost:4873 <package>
```

Bins: `sentinel-proxy` (the server) and `sentinel-registry`
(`import`/`export` migration utility). Configuration is via `SENTINEL_*`
environment variables — see the
[Sentinel repository](https://github.com/git-agentic/pkg-registry) for the
full reference, architecture, and threat model.

## License

Apache-2.0

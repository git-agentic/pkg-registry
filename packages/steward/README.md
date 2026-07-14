# @git-agentic/sentinel-steward

`sentinel-steward`: the Sentinel namespace-claim steward — an authenticated
operational service for exact-apex DNS TXT claim challenges, three-tier
grandfathering, claimant-key-signed transfers, 12-month renewal and freeze
lifecycle, 30-day timelocked changes, and atomic Ed25519-signed claim- and
retraction-corpus releases that Sentinel proxies consume offline.

> **Alpha.** This is a pre-1.0 alpha preview. APIs may change
> without notice. Not production-ready.

```bash
npm install -g @git-agentic/sentinel-steward@alpha
```

All four variables are required:

```bash
SENTINEL_STEWARD_TOKEN=operator-secret \
SENTINEL_STEWARD_STATE=./steward/state.json \
SENTINEL_CLAIM_CORPUS_PRIVATE_KEY=./steward/private.pem \
SENTINEL_CLAIM_CORPUS_RELEASE_DIR=./steward/release \
sentinel-steward
```

See the [Sentinel repository](https://github.com/git-agentic/pkg-registry)
for the claim lifecycle, corpus format, and threat model.

## License

Apache-2.0

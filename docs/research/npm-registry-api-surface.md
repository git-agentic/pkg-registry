# npm registry API surface — what real clients require

- **Date:** 2026-07-11
- **Question:** What is the exact HTTP surface a registry must speak for npm / pnpm / yarn (Berry & Classic) / bun clients to work unmodified?
- **Resolves:** [git-agentic/pkg-registry#34](https://github.com/git-agentic/pkg-registry/issues/34) (part of #33)
- **Method:** Primary sources only — npm/registry docs, npm CLI workspaces (libnpmpublish, libnpmaccess, libnpmsearch, arborist, npm-profile), pacote, npm-registry-fetch, pnpm monorepo (`pnpm11/` TS packages), yarnpkg/berry plugin-npm, yarnpkg/yarn, oven-sh/bun install/publish source, plus live verification against `registry.npmjs.org`. Every claim cites its source inline. Classification is from Sentinel's standpoint: **native write-path registry for private namespaces, continuing to proxy public npm reads.**

## Summary table

Classification: **MUST** = install or publish breaks without it (implement natively for private namespaces); **proxyable** = Sentinel can forward to registry.npmjs.org unchanged; **ignorable** = clients degrade gracefully (degradation evidence in the sections below).

| Route | Verb | Who calls it | Load-bearing for install? | Classification |
|---|---|---|---|---|
| `/{package}` (packument; corgi Accept negotiation) | GET | npm, pnpm, yarn 1, yarn Berry, bun | **Yes** | **MUST** (private) / proxyable (public) |
| `dist.tarball` URL (convention: `/{package}/-/{name}-{version}.tgz`) | GET | npm, pnpm, yarn 1, yarn Berry, bun | **Yes** | **MUST** (private) / proxyable (public) |
| `/{package}/{version}` (single-version manifest) | GET | none of the four install paths | No | ignorable |
| `/{package}` (publish body with `_attachments`) | PUT | npm, pnpm (via libnpmpublish), yarn Berry, bun | Publish breaks | **MUST** |
| `/-/stage/package/{package}` (staged publish, opt-in) | POST | npm `--stage`, pnpm `--stage`/`--batch` | No | ignorable |
| `/{package}/-rev/{rev}` (unpublish whole pkg / rewrite packument) | DELETE / PUT | npm, pnpm unpublish | No | **MUST** (write path) |
| `{tarball}/-rev/{rev}` (delete one tarball) | DELETE | npm, pnpm unpublish | No | **MUST** (write path) |
| `/{package}?write=true` → PUT `/{package}` (deprecate) | GET+PUT | npm deprecate | No | **MUST** (write path) |
| `/-/package/{spec}/dist-tags[/{tag}]` | GET / PUT / DELETE | npm dist-tag | No | **MUST** (write path) |
| `/-/user/org.couchdb.user:{user}` | PUT | npm (legacy fallback), pnpm login, yarn Berry login | No | **MUST** (auth bootstrap) |
| `/-/v1/login` + polled `doneUrl` | POST + GET | npm (default web flow), Berry `--web-login`, bun (web OTP) | No | proxyable (legacy fallback exists) |
| `/-/whoami` | GET | npm whoami, Berry auth-error path | No | ignorable |
| `/-/npm/v1/security/advisories/bulk` | POST | npm/arborist, pnpm audit, Berry audit, bun audit | No (fails soft) | proxyable |
| `/-/v1/search` | GET | npm search | No | proxyable |
| `/-/ping` | GET | npm ping / doctor | No | ignorable |
| `/-/npm/v1/keys` | GET | npm `audit signatures` (TUF fallback) | No | proxyable |
| `/-/npm/v1/attestations/{name}@{version}` (via `dist.attestations.url`) | GET | npm with `verifyAttestations` | No | proxyable |
| `/-/npm/v1/user`, `/-/npm/v1/tokens[...]` | GET/POST/DELETE | npm profile / token | No | ignorable |
| `/-/package/{spec}/access·collaborators·visibility`, `/-/team/...`, `/-/org/...` | GET/PUT/POST | npm access | No | ignorable |
| `api.npmjs.org/downloads/{point,range}/...` | GET | tooling, not package managers | No | ignorable (different host) |

## (a) Read / install path

### Packument: `GET /{package}`

All five clients resolve a package by fetching the packument from `{registry}/{escaped-name}`. Scoped names keep the `@` and encode the slash: pacote uses `this.spec.escapedName` appended to the registry ([npm/pacote `lib/registry.js`](https://github.com/npm/pacote/blob/main/lib/registry.js): `` `${removeTrailingSlashes(this.registry)}/${this.spec.escapedName}` ``); Yarn Berry's `getIdentUrl` builds `` `/@${encodeURIComponent(ident.scope)}%2f${encodeURIComponent(ident.name)}` `` for scoped and `` `/${encodeURIComponent(ident.name)}` `` for unscoped ([yarnpkg/berry `packages/plugin-npm/sources/npmHttpUtils.ts`](https://github.com/yarnpkg/berry/blob/master/packages/plugin-npm/sources/npmHttpUtils.ts)).

**Exact Accept strings sent, per client:**

| Client | Accept header on metadata GET | Source |
|---|---|---|
| npm (pacote) | `application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*` (corgi); `application/json` when `fullMetadata` | [npm/pacote `lib/registry.js`](https://github.com/npm/pacote/blob/main/lib/registry.js) constants `corgiDoc` / `fullDoc` |
| pnpm | identical corgi string: `ABBREVIATED_DOC = 'application/vnd.npm.install-v1+json'`, `ACCEPT_ABBREVIATED_DOC = `${ABBREVIATED_DOC}; q=1.0, ${FULL_DOC}; q=0.8, */*``; full = `application/json; q=1.0, */*`. Set **only** on GET/HEAD — pnpm's code comments that setting it on writes "breaks npmjs.org's dist-tag endpoint, which rejects the request with a generic 400" | [pnpm/pnpm `pnpm11/network/fetch/src/fetchFromRegistry.ts`](https://github.com/pnpm/pnpm/blob/main/pnpm11/network/fetch/src/fetchFromRegistry.ts) lines 12–16, 147–152 |
| yarn 1 (Classic) | same corgi string unless `opts.unfiltered`, then `application/json` | [yarnpkg/yarn `src/registries/npm-registry.js`](https://github.com/yarnpkg/yarn/blob/master/src/registries/npm-registry.js) |
| yarn Berry | **no corgi header at all** — Berry requests the full packument. `npmHttpUtils.ts` sets no install-v1 Accept anywhere, and an org-wide code search for `install-v1` in yarnpkg/berry matches only a docusaurus config. Berry caches a projection on disk (`CACHED_FIELDS`: `dependencies`, `dependenciesMeta`, `optionalDependencies`, `peerDependencies`, `peerDependenciesMeta`, `deprecated`, plus `dist.tarball`, `dist-tags`, and optional `time`) under `metadata/npm/{CACHE_KEY}/{hostname}` | [yarnpkg/berry `packages/plugin-npm/sources/npmHttpUtils.ts`](https://github.com/yarnpkg/berry/blob/master/packages/plugin-npm/sources/npmHttpUtils.ts) (`getPackageMetadata`, `CACHED_FIELDS`, `CACHE_KEY`) |
| bun | `const ACCEPT_HEADER_VALUE: &str = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"` — the fallback q-values were added deliberately after registries 406'd on the bare value ([oven-sh/bun#341](https://github.com/oven-sh/bun/issues/341)); an "extended manifest" mode sends `application/json, */*`. Bun also sends `If-None-Match` (ETag) / `If-Modified-Since` revalidation headers from its manifest cache | [oven-sh/bun `src/install/NetworkTask.rs`](https://github.com/oven-sh/bun/blob/main/src/install/NetworkTask.rs) lines 347–358, 541–592 |

**Content-Type echo is contractually meaningful.** A registry that honors the abbreviated Accept must echo `Content-Type: application/vnd.npm.install-v1+json`; pnpm detects that echo and, when absent, assumes the registry ignored the header and strips the full document down to the abbreviated field set itself ([pnpm `pnpm11/resolving/npm-resolver/src/fetch.ts`](https://github.com/pnpm/pnpm/blob/main/pnpm11/resolving/npm-resolver/src/fetch.ts): `ABBREVIATED_META_CONTENT_TYPE`). Verified live: `curl -sI -H 'Accept: application/vnd.npm.install-v1+json; …' https://registry.npmjs.org/semver` → `content-type: application/vnd.npm.install-v1+json`, plus `etag` and `last-modified` (which bun's conditional requests use).

**Abbreviated packument contents** (registry spec, [npm/registry `docs/responses/package-metadata.md`](https://github.com/npm/registry/blob/master/docs/responses/package-metadata.md)): top-level `name`, `modified`, `dist-tags`; per-version `name`, `version`, `dependencies`, `optionalDependencies`, `peerDependencies`, `engines`, `deprecated`, `_hasShrinkwrap`, and `dist` with `tarball`, `shasum` (SHA-1), `integrity` (SRI, since Apr 2017), and file count / unpacked size / signature fields. The full document additionally carries `time` (per-version publish timestamps), `readme`, and arbitrary manifest fields. **Because Yarn Berry fetches the full document and reads `registryData.time`, a registry that can only produce abbreviated documents degrades Berry** (its `time`-dependent features; the field is typed optional, so resolution still works).

### Tarball: `GET dist.tarball`

Clients do not construct tarball URLs — they dereference `dist.tarball` from the packument verbatim: pacote sets `this.resolved = mani._resolved = dist.tarball` ([npm/pacote `lib/registry.js`](https://github.com/npm/pacote/blob/main/lib/registry.js)); Berry's resolver reads `.dist.tarball` per version ([`NpmSemverResolver.ts`](https://github.com/yarnpkg/berry/blob/master/packages/plugin-npm/sources/NpmSemverResolver.ts)). The public-registry convention is `/{package}/-/{name}-{version}.tgz` (scoped: `/@scope/name/-/name-version.tgz`), which is also what publishers write into `dist.tarball` (see §b). Integrity is enforced client-side against `dist.integrity`/`dist.shasum`. This is exactly the seam Sentinel already rewrites (ADR-0036).

### `GET /{package}/{version}`

Documented in [npm/registry `docs/REGISTRY-API.md`](https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md) (version may be `latest`), but none of the four package managers' install paths use it — pacote, pnpm, Berry, and bun all resolve from the packument. Ignorable for client compatibility.

### `dist.signatures` and `dist.attestations` (read-side trust data)

- `dist.signatures: [{keyid, sig}]` — ECDSA (`ecdsa-sha2-nistp256`) signature over `${package.name}@${package.version}:${package.dist.integrity}`; keys published at `{registry}/-/npm/v1/keys` ([docs.npmjs.com/about-registry-signatures](https://docs.npmjs.com/about-registry-signatures/)). npm verifies only when asked (`--verify-signatures` / `npm audit signatures`); pacote checks `${mani._id}:${mani._integrity}` against configured keys and throws `EMISSINGSIGNATUREKEY` if a signature's key is unknown ([npm/pacote `lib/registry.js`](https://github.com/npm/pacote/blob/main/lib/registry.js)).
- `dist.attestations: {url, provenance: {predicateType}}` — verified live on `sigstore@5.0.0`: `url` is `https://registry.npmjs.org/-/npm/v1/attestations/sigstore@5.0.0`. When `verifyAttestations` is set, pacote takes **only the pathname** of `dist.attestations.url` and re-roots it on the configured registry (`new URL(new URL(dist.attestations.url).pathname, this.registry).href`), then expects a JSON body `{attestations: [{predicateType, bundle}]}` where `bundle` is a Sigstore bundle with `dsseEnvelope` ([npm/pacote `lib/registry.js`](https://github.com/npm/pacote/blob/main/lib/registry.js)). Verified live: the endpoint returns `{"attestations":[{"predicateType":"https://github.com/npm/attestation/tree/main/specs/publish/v0.1","bundle":{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.2",...}},...]}`.

Neither is load-bearing for install: both are opt-in verification paths.

## (b) Publish path: `PUT /{package}`

Authoritative implementation: [npm/cli `workspaces/libnpmpublish/lib/publish.js`](https://github.com/npm/cli/blob/latest/workspaces/libnpmpublish/lib/publish.js). The request is `PUT {registry}/{spec.escapedName}` with a JSON body:

```jsonc
{
  "_id": "<name>",
  "name": "<name>",
  "description": "...",
  "access": null | "public" | "restricted",
  "dist-tags": { "<tag>": "<version>" },          // root['dist-tags'][defaultTag] = manifest.version
  "versions": {
    "<version>": {
      // full manifest, patched with:
      "dist": {
        "integrity": "sha512-…",                   // ssri, sha512 (string form)
        "shasum": "…",                             // sha1 hex, legacy
        "tarball": "http://…/<name>/-/<name>-<version>.tgz"
        // note: libnpmpublish builds this with new URL(tarballURI, registry).href
        // and then replaces https:// with http:// — registries are expected to
        // normalize/rewrite the stored tarball URL themselves
      }
    }
  },
  "_attachments": {
    "<name>-<version>.tgz": {
      "content_type": "application/octet-stream",
      "data": "<base64 tarball bytes>",
      "length": <tarball byte length>
    }
  }
}
```

- Integrity computed as `ssri.fromData(tarballData, { algorithms: [...new Set(['sha1'].concat(algorithms))] })` — the registry can recompute and must at minimum store/serve `integrity` (sha512) and `shasum` (sha1).
- **Provenance:** when `provenance`/`provenanceFile` is set, a **second attachment** rides in the same PUT: key `${name}-${version}.sigstore`, `content_type` = the bundle's `mediaType`, `data` = the JSON-stringified Sigstore bundle, `length` = its serialized length (libnpmpublish, same file). The registry is what later exposes this as `dist.attestations` + the `/-/npm/v1/attestations/…` document (§a); npm's user-facing description is at [docs.npmjs.com/generating-provenance-statements](https://docs.npmjs.com/generating-provenance-statements).
- **Staged publish (new, opt-in):** `opts.stage` switches the same body to `POST /-/stage/package/${spec.escapedName}`; the response JSON carries `stageId` (libnpmpublish `lib/publish.js`: `` const stageRoute = `/-/stage/package/${spec.escapedName}` ``). pnpm's `--stage`/`--batch` flows use this via libnpmpublish. Optional surface.

**Other clients' publish bodies confirm the same wire shape:**

- **Yarn Berry** (`makePublishBody`, [yarnpkg/berry `packages/plugin-npm/sources/npmPublishUtils.ts`](https://github.com/yarnpkg/berry/blob/master/packages/plugin-npm/sources/npmPublishUtils.ts)): `_id`, `name`, `access` (scoped default `restricted`, else `public`), `dist-tags`, `versions`, `readme`, optional `gitHead`; `_attachments` with `content_type: application/octet-stream` / base64 `data` / `length`; `dist.shasum` (SHA1 hex), `dist.integrity` (SHA512), `dist.tarball` = `${registry}/${name}/-/${name}-${version}.tgz`; provenance as a `.sigstore` attachment whose subject is `pkg:npm/${name}@${version}` (scoped `@` escaped as `%40`).
- **bun** (`construct_publish_request_body`, [oven-sh/bun `src/runtime/cli/publish_command.rs`](https://github.com/oven-sh/bun/blob/main/src/runtime/cli/publish_command.rs)): emits exactly `{"_id":…,"name":…,"dist-tags":{tag:version},"versions":{v: normalized pkg info},"access":"…"|null,"_attachments":{"<name>-<version>.tgz":{"content_type":"application/octet-stream","data":"<base64>","length":N}}}`; SHA1 shasum + SHA512 integrity computed in `normalized_package`. Request: `PUT {registry-without-trailing-slash}/{escaped-name}` with headers `content-type: application/json` (comment: "verdaccio will fail if it's anything other than application/json"), `npm-auth-type: web|legacy`, `npm-command: publish`, optional `npm-otp`, `authorization: Bearer <token>` or `Basic <auth>`. On 4xx it inspects the response for OTP challenges (web-auth flow: polls a `done` URL with GET until 200, parsing a token — `get_otp`, same file). No provenance/sigstore code exists in bun's publish path (negative evidence: grep for `sigstore`/`attestation` over the file finds nothing).
- **pnpm** publishes natively **through libnpmpublish** — `pnpm11/releasing/commands/src/publish/publishPackedPkg.ts` imports `PublishOptions` from `libnpmpublish` and sends headers `npm-auth-type: web`, `npm-command: publish|stage` ([pnpm/pnpm `pnpm11/releasing/commands/src/publish/publishPackedPkg.ts`](https://github.com/pnpm/pnpm/blob/main/pnpm11/releasing/commands/src/publish/publishPackedPkg.ts)). So one PUT-body implementation covers npm and pnpm.

**Response contract:** all four treat any 2xx as success (npm-registry-fetch throws on non-2xx; bun branches on `res.status_code >= 400` and retries once with an OTP). npmjs's specific error statuses (e.g. republishing an existing version) are not documented in a primary source I could find — see gaps. bun additionally preflights `GET {registry}/{name}` and checks `json.versions[version]` when `tolerate_republish` is set (publish_command.rs `check_package_version_exists`).

## (c) Auth routes and token semantics

- **Web login (npm default):** `POST /-/v1/login` (npm sends header `npm-auth-type: web`) → response `{loginUrl, doneUrl}`; client opens `loginUrl`, polls `doneUrl` with GET; **202 + `retry-after` header** = keep polling, **200 + `{token}`** = done. Owned by [npm/npm-profile `lib/index.js`](https://github.com/npm/npm-profile/blob/main/lib/index.js); Yarn Berry implements the identical flow in [`plugin-npm-cli/sources/commands/npm/login.ts`](https://github.com/yarnpkg/berry/blob/master/packages/plugin-npm-cli/sources/commands/npm/login.ts) (`webLoginInit` posts `/-/v1/login`, `webLoginCheck` honors 202/`retry-after`/200). If the POST fails, Berry returns null and falls back to the classic flow — so a registry without `/-/v1/login` still supports login.
- **Legacy CouchDB login/adduser:** `PUT /-/user/org.couchdb.user:{username}` with body `{_id: "org.couchdb.user:<name>", name, password, type: "user", roles: [], date}`; success returns `{token}`. On 409 conflict: `GET /-/user/org.couchdb.user:{username}?write=true`, merge, re-`PUT …/-rev/{_rev}` (npm-profile, same file). pnpm implements this natively ([pnpm `pnpm11/registry-access/client/src/addUser.ts`](https://github.com/pnpm/pnpm/blob/main/pnpm11/registry-access/client/src/addUser.ts): `` new URL(`-/user/org.couchdb.user:${encodeURIComponent(opts.username)}`, opts.registryUrl) ``, errors if the 2xx response lacks `token`); Berry's classic path cites npm-profile verbatim and PUTs the same body (login.ts lines ~217–224). **This is the lowest common denominator — implement it and every client can log in.**
- **Token usage:** all clients send `Authorization: Bearer <token>` (or `Basic <base64>` for username/password `_auth`) — Berry (`npmHttpUtils.getAuthenticationHeader`: hook → `Bearer ${npmAuthToken}` → `Basic ${npmAuthIdent b64}` → OIDC bearer), bun (`append_auth`: `Bearer`/`Basic` + companion header `npm-auth-type: legacy`), yarn 1 (`_authToken` bearer → `_auth` basic → username/`_password`), npm/pnpm via npm-registry-fetch config. Bun reads `.npmrc` and `bunfig.toml` scoped registries ([bun.sh/docs/install/registries](https://bun.sh/docs/install/registries)).
- **OTP:** clients send the `npm-otp: <code>` header after a 401 whose `www-authenticate` contains `otp` (Berry npmHttpUtils; bun publish_command.rs; npm via `otplease`).
- **`GET /-/whoami`** → `{username}`. Used by `npm whoami` and by Berry only to decorate auth-error messages — Berry catches failure and prints "an unknown user" (npmHttpUtils.ts `whoami()`), so absence degrades gracefully.
- **Profile/tokens:** `GET/POST /-/npm/v1/user`, `GET/POST /-/npm/v1/tokens`, `DELETE /-/npm/v1/tokens/token/{key}` (npm-profile). Only `npm profile`/`npm token` call these; ignorable.

## (d) Mutation routes

All mutation reads use the `?write=true` query so registries serve an un-cached, `_rev`-bearing document.

- **dist-tag** ([npm/cli `lib/commands/dist-tag.js`](https://github.com/npm/cli/blob/latest/lib/commands/dist-tag.js)):
  - list: `GET /-/package/${spec.escapedName}/dist-tags`
  - add: `PUT /-/package/${spec.escapedName}/dist-tags/${encodeURIComponent(tag)}` — body is `JSON.stringify(version)` (a bare JSON string), header `content-type: application/json`
  - rm: `DELETE /-/package/${spec.escapedName}/dist-tags/${encodeURIComponent(tag)}`
  - Interop trap: npmjs 400s this endpoint if the abbreviated Accept header is present (pnpm's comment, §a) — don't require corgi Accept on writes.
- **deprecate** ([npm/cli `lib/commands/deprecate.js`](https://github.com/npm/cli/blob/latest/lib/commands/deprecate.js)): `GET /{escapedName}?write=true` (full packument), set `packument.versions[v].deprecated = msg` on every semver-matching version, then `PUT /{escapedName}` with the whole modified packument. There is no dedicated deprecate route — deprecate **is** a packument overwrite, so the PUT handler must accept a full packument with `_rev`/`_id` present.
- **unpublish** ([npm/cli `workspaces/libnpmpublish/lib/unpublish.js`](https://github.com/npm/cli/blob/latest/workspaces/libnpmpublish/lib/unpublish.js)):
  - fetch: `npmFetch.json(pkgUri, { query: { write: true } })`
  - whole package: `DELETE ${pkgUri}/-rev/${pkg._rev}`
  - single version (the "-rev dance"): delete the version from `versions`, retarget `dist-tags`, then `PUT ${pkgUri}/-rev/${pkg._rev}` with the modified packument, then `DELETE ${tarballUrl}/-rev/${_rev}` (tarball URL taken from the removed version's `dist.tarball`; last-version case degenerates to the whole-package DELETE).
  - Consequence: packuments served on the write path must carry `_rev`, and the registry must route `/-rev/{rev}` suffixes on both packument and tarball paths. pnpm's native `pnpm unpublish` does the same packument+`_rev` fetch ([pnpm `pnpm11/registry-access/commands/src/unpublish.ts`](https://github.com/pnpm/pnpm/blob/main/pnpm11/registry-access/commands/src/unpublish.ts)).
- **access** ([npm/cli `workspaces/libnpmaccess/lib/index.js`](https://github.com/npm/cli/blob/latest/workspaces/libnpmaccess/lib/index.js)): `GET /-/package/${spec.escapedName}/collaborators`, `GET/POST /-/package/${spec.escapedName}/visibility` and `/access`, `PUT/DELETE /-/team/${scope}/${team}/package`, `GET /-/org/${scope}/package`, `GET /-/user/${scope}/package`. Only the `npm access` command uses these; install/publish never do — ignorable.

## (e) Optional / telemetry surface

- **Audit — the bulk endpoint is the only one modern clients use:** `POST {registry}/-/npm/v1/security/advisories/bulk`, gzip body of `{ "<pkg-name>": ["<version>", …], … }` → response keyed by package name with advisory objects.
  - npm: [arborist `lib/audit-report.js`](https://github.com/npm/cli/blob/latest/workspaces/arborist/lib/audit-report.js) — `npmFetch('/-/npm/v1/security/advisories/bulk', { registry: this.options.auditRegistry || this.options.registry, method: 'POST', gzip: true, body })`. **Failure is swallowed** (`this.error = er; return null`) — `npm install` completes with no audit output when the endpoint is absent. The legacy `POST /-/npm/v1/security/audits/quick` endpoint appears **nowhere** in current arborist (npm v6 era only).
  - pnpm: `` const auditUrl = `${registry}-/npm/v1/security/advisories/bulk` `` ([pnpm `pnpm11/deps/compliance/audit/src/index.ts`](https://github.com/pnpm/pnpm/blob/main/pnpm11/deps/compliance/audit/src/index.ts)).
  - Yarn Berry: `yarn npm audit` posts the same route against `npmConfigUtils.getAuditRegistry(...)` ([`plugin-npm-cli/sources/commands/npm/audit.ts`](https://github.com/yarnpkg/berry/blob/master/packages/plugin-npm-cli/sources/commands/npm/audit.ts)).
  - bun: `write!(url_str, "{}/-/npm/v1/security/advisories/bulk", …scope.url…)` ([oven-sh/bun `src/runtime/cli/audit_command.rs`](https://github.com/oven-sh/bun/blob/main/src/runtime/cli/audit_command.rs)); unparseable responses exit 1 with "Is the registry down?" — only the explicit `bun audit` command is affected, never install.
- **Search:** `GET /-/v1/search?text=&size=&from=&quality=&popularity=&maintenance=` → `{objects: [...], total, time}` ([npm/registry `docs/REGISTRY-API.md`](https://github.com/npm/registry/blob/master/docs/REGISTRY-API.md); client params in [npm/cli `workspaces/libnpmsearch/lib/index.js`](https://github.com/npm/cli/blob/latest/workspaces/libnpmsearch/lib/index.js), defaults `size=20, quality=0.65, popularity=0.98, maintenance=0.5`). Only `npm search`; install unaffected.
- **Ping:** `GET /-/ping` — [npm/cli `lib/utils/ping.js`](https://github.com/npm/cli/blob/latest/lib/utils/ping.js) is four lines: `npmFetch('/-/ping', { ...flatOptions, cache: false })`, JSON parse errors swallowed (`res.json().catch(() => ({}))`). Used by `npm ping` and `npm doctor` only.
- **Signing keys:** `GET /-/npm/v1/keys` → `{keys: [{keyid, keytype, scheme, key, expires}]}` ([docs.npmjs.com/about-registry-signatures](https://docs.npmjs.com/about-registry-signatures/)). `npm audit signatures` first tries the Sigstore TUF repo target `{host}{path}/keys.json` and only falls back to this route; **E404/E400 → `null` → treated as "registry provides no signing keys"** — fully graceful ([npm/cli `lib/utils/verify-signatures.js`](https://github.com/npm/cli/blob/latest/lib/utils/verify-signatures.js) `setKeys`).
- **Download counts:** served from a **different host** — `GET https://api.npmjs.org/downloads/point/{period}[/{package}]`, `/downloads/range/…`, `/versions/{package}/last-week` ([npm/registry `docs/download-counts.md`](https://github.com/npm/registry/blob/master/docs/download-counts.md)). No package manager calls these; nothing for a registry to implement.

## Confidence & gaps

Confirmed with direct source quotes or live probes: everything in §a, §b (bodies for npm/Berry/bun, pnpm's libnpmpublish delegation), §d routes, audit/search/ping/keys routes, and the live `dist.attestations` / corgi Content-Type / ETag behavior of registry.npmjs.org.

Explicitly lower-confidence or unconfirmed:

1. **npm publish error-status contract** (e.g. exact status for republishing an existing version — 403 vs 409 on npmjs). libnpmpublish just throws on non-2xx; I found no primary doc of npmjs's specific codes. Sentinel should treat any 4xx as failure-with-body and not rely on a specific code.
2. **npm CLI's exact fallback trigger from web login to CouchDB login** — npm-profile implements both flows; the precise error codes that trigger fallback (`webAuthNotSupported` detection) were summarized, not quoted line-by-line. Berry's fallback (any error on `POST /-/v1/login` → classic) is quoted directly.
3. **Yarn Berry never sends the corgi Accept** — negative evidence (grep of `npmHttpUtils.ts` + org-wide code search matching only docusaurus config). High confidence but it is proof-by-absence.
4. **bun publish has no provenance support** — negative evidence from grepping `publish_command.rs` for sigstore/attestation. bun's docs were not checked for a contrary claim.
5. **`POST /-/stage/package/{pkg}` response/lifecycle beyond `{stageId}`** (how a stage is promoted) — only the client half is visible in libnpmpublish; the server contract is not publicly documented.
6. **Quick audit endpoint** (`/-/npm/v1/security/audits/quick`) being npm-v6-only is inferred from its absence in current arborist; the v6 client itself was not audited.
7. The old **PGP `npm-signature`** dist field is documented in package-metadata.md but npm is migrating off it (docs.npmjs.com); treated as legacy, not verified further.

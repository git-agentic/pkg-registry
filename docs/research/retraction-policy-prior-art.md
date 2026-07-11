# Retraction / yank / unpublish policies across package registries — prior art

- **Date:** 2026-07-11
- **Question:** What retraction/yank/unpublish policies exist across package registries, what windows and conditions do they use, and what broke? Context: Sentinel plans retraction allowed only within a window bounded by **both** elapsed time **and** cumulative download count, immutability after, with already-fetched installers seeing a tombstone + advisory.
- **Resolves:** [git-agentic/pkg-registry#36](https://github.com/git-agentic/pkg-registry/issues/36) (part of #33)
- **Method:** Primary sources only — official registry policy texts, PEPs and Rust RFCs, the Go modules reference and proxy/sumdb pages, client source (pip, cargo), and first-party postmortems. Every window/condition is quoted verbatim with its source cited inline. This file extracts mechanics and failure modes; it makes **no** design recommendations for Sentinel (that is a later ticket).

## 1. npm — windowed unpublish (time + usage conditions), deprecate as the steady state

### Current policy (docs.npmjs.com, as of 2026-07-11)

The [npm unpublish policy](https://docs.npmjs.com/policies/unpublish/) sets a 72-hour free window:

> "For newly created packages, as long as no other packages in the npm Public Registry depend on your package, you can unpublish anytime within the first 72 hours after publishing."

After 72 hours a package/version can be unpublished only if it meets **all** of ([policy](https://docs.npmjs.com/policies/unpublish/)):

> - "no other packages in the npm Public Registry depend on it"
> - "it had less than 300 downloads over the last week"
> - "it has a single owner/maintainer"

npm is the only surveyed registry whose window has **usage** conditions (dependents + a download threshold) in addition to time — see §7.2.

**Name/version after unpublish** ([policy](https://docs.npmjs.com/policies/unpublish/)):

> "Once `package@version` has been used, you can never use it again. You must publish a new version even if you unpublished the old one."

> "If you entirely unpublish all versions of a package, you may not publish any new versions of that package until 24 hours have passed."

So the *version* coordinate is tombstoned forever, but the *name* is re-claimable by anyone after 24 hours — a known squatting seam that npm plugs case-by-case (see the security placeholder below).

**Recommended alternative** ([policy](https://docs.npmjs.com/policies/unpublish/); also [Unpublishing packages from the registry](https://docs.npmjs.com/unpublishing-packages-from-the-registry)):

> "If your package does not meet the unpublish policy criteria, we recommend deprecating the package. This allows the package to be downloaded but publishes a clear warning message (that you get to write) every time the package is downloaded, and on the package's npmjs.com page."

**Registry-side removal (malware) is a separate mechanism.** When npm Security confirms malware it will ([Reporting malware in an npm package](https://docs.npmjs.com/reporting-malware-in-an-npm-package/)):

> "Remove the package from the registry." … "Publish a security placeholder for the package." … "Publish a security advisory alerting the community."

The "security placeholder" (the `0.0.1-security` holding package seen on npmjs.com) exists precisely because plain unpublish frees the name after 24 hours; publishing a placeholder is how npm makes a removal *stick* against re-registration.

### The left-pad incident (2016) and the policy it produced

Primary source: npm's own postmortem, ["kik, left-pad, and npm"](https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm) (Isaac Z. Schlueter, 2016-03-23). After a package-name dispute over `kik`, the author unpublished all 273 of his packages, including `left-pad@0.0.3`, which sat under a huge fraction of the ecosystem (Babel, React tooling, etc.). The post reports installs failing at a rate of "hundreds of failures per minute" for about two and a half hours. A community member republished `left-pad` as 1.0.0 within minutes, but dependents pinned to `0.0.3` stayed broken until npm took "the unprecedented step" of restoring the original `0.0.3` from backup — the **un-un-publish**. The post commits to policy changes:

> "We will make it harder to un-publish a version of a package if doing so would break other packages."

plus placeholder packages for fully-unpublished names that have dependents, and better internal conflict-handling. At the time of the incident there was **no** unpublish restriction at all — any author could delete anything at any age.

The concrete follow-up is ["changes to npm's unpublish policy"](https://blog.npmjs.org/post/141905368000/changes-to-npms-unpublish-policy) (npm, 2016-03-30), which introduced the first window:

> "If the version is less than 24 hours old, you can unpublish it. The package will be completely removed from the registry."

> "If the version is older than 24 hours, then the unpublish will fail, with a message to contact support@npmjs.com."

Rationale, verbatim:

> "A byproduct of being so interdependent is that a single actor can wreak significant havoc across the ecosystem."

> "npm exists to facilitate a productive community. That means we must balance individual ownership with collective benefit."

The window was later widened from 24 h + manual support to today's 72 h + mechanical usage conditions (no dependents, <300 downloads/week, single owner); I found no first-party dated announcement of that transition (see §8).

**What already-fetched installers see after an npm unpublish:** nothing graceful. The version vanishes from the packument and the tarball 404s; any lockfile referencing it fails on the next cold install. That is exactly the left-pad failure mode, now merely bounded by the window conditions.

## 2. crates.io — metadata-only yank over immutable bytes, plus a recently added windowed owner-delete

### Yank

[`cargo yank`](https://doc.rust-lang.org/cargo/commands/cargo-yank.html) is explicitly non-destructive:

> "The yank command removes a previously published crate's version from the server's index. This command does not delete any data, and the crate will still be available for download via the registry's download link."

("Removes from the index" is loose wording — see below: the index *entry* stays, its `yanked` flag flips.)

> "Cargo will not use a yanked version for any new project or checkout without a pre-existing lockfile, and will generate an error if there are no longer any compatible versions for your crate."

Existing `Cargo.lock` files keep resolving the yanked version; only fresh resolutions exclude it. Yank is reversible:

> "`--undo` — Undo a yank, putting a version back into the index."

Pinned users: the cargo-yank man page's behavior table shows that with an exact requirement `bar = "=1.5.0"`, yanking 1.5.0 makes resolution **"Return Error"** (unlike caret requirements, which slide to 1.5.1/1.5.2). The escape hatch is [`cargo update --precise`](https://doc.rust-lang.org/cargo/commands/cargo-update.html):

> "While not recommended, you can specify a yanked version of a package. When possible, try other non-yanked SemVer-compatible versions or seek help from the maintainers of the package."

Intended scope of yank, verbatim ([cargo-yank](https://doc.rust-lang.org/cargo/commands/cargo-yank.html)):

> "Crates should only be yanked in exceptional circumstances, for example, an accidental publish, unintentional SemVer breakages, or a significantly broken and unusable crate. In the case of security vulnerabilities, RustSec is typically a less disruptive mechanism to inform users and encourage them to upgrade."

**Index mechanics** ([Registry index format](https://doc.rust-lang.org/cargo/reference/registry-index.html)): each version's JSON line carries `cksum` ("A SHA256 checksum of the `.crate` file.") and `yanked` ("Boolean of whether or not this version has been yanked."). Yanking flips the flag in place; checksums and the entry itself persist:

> "The JSON objects should not be modified after they are added except for the `yanked` field whose value may change at any time."

This is how mirrors and offline corpora learn of a yank: an index diff, with bytes and checksums unchanged.

**Diagnostics:** there is no dedicated RFC for yanked-version diagnostics that I could confirm (the "RFC 3016" pointer in the brief did not check out — §8). The actual mechanisms are in cargo itself: Cargo 1.37 "Warnings have been added if yanked dependencies are detected" when publishing/installing with a lockfile ([cargo CHANGELOG](https://github.com/rust-lang/cargo/blob/master/src/doc/src/CHANGELOG.md), [#6840](https://github.com/rust-lang/cargo/pull/6840)), and the current warning text in [`src/cargo/ops/cargo_package/mod.rs`](https://github.com/rust-lang/cargo/blob/master/src/cargo/ops/cargo_package/mod.rs) is:

> `package `{pkg_id}` in Cargo.lock is yanked in registry `{name}``

### Deletion

Historic policy ([RFC 3463, crates.io policy update, 2023](https://rust-lang.github.io/rfcs/3463-crates-io-policy-update.html)):

> "Crate deletion by their owners is not possible to keep the registry as immutable as possible."

with team-side removal reserved for policy violations:

> "The crates.io team may delete crates from the registry that do not comply with the policies on this document."

> "In all cases, content and account deletion is permanent and there is no basis to reverse these moderation actions taken by the crates.io team."

That immutability stance was then partially reversed for owners by [RFC 3660, crates.io crate deletions](https://rust-lang.github.io/rfcs/3660-crates-io-crate-deletions.html) (accepted 2024), motivated by accidental publishes, test crates, unintended disclosure, and renames. RFC text, verbatim: deletion allowed if "The crate has been published for less than 72 hours", or otherwise if all of "The crate has a single owner", "The crate is not depended upon by any other crate on crates.io", and "The crate has been downloaded less than 100 times for each month it has been published."

Shipped and since tuned: the [Feb 2025 crates.io development update](https://blog.rust-lang.org/2025/02/05/crates-io-development-update/) announced the feature (web UI + `DELETE /api/v1/crates/:name`) with the threshold at "downloaded less than 500 times for each month it has been published"; the current deletion page in the crates.io frontend ([`svelte/src/routes/crates/[crate_id]/delete/+page.svelte`](https://github.com/rust-lang/crates.io/blob/main/svelte/src/routes/crates/%5Bcrate_id%5D/delete/%2Bpage.svelte)) reads:

> "A crate can only be deleted if it is not depended upon by any other crate on crates.io." … either "the crate has been published for less than 72 hours" or "the crate only has a single owner, *and* the crate has been downloaded less than 1000 times for each month it has been published."

Note the shape: a hard no-dependents gate, then **time window OR rate-normalized download threshold** — downloads-per-month-published, i.e. cumulative downloads divided by age, not a raw cumulative cap. The threshold drifted 100 → 500 → 1000 across RFC → launch → today (§8).

## 3. PyPI — PEP 592 yank as the designed alternative to delete; delete still exists

### PEP 592 (yanked releases)

[PEP 592](https://peps.python.org/pep-0592/) designed yank explicitly because deletion breaks pinned users. Motivation, verbatim:

> "Whenever a project detects that a particular release on PyPI might be broken, they oftentimes will want to prevent further users from inadvertently using that version. However, the obvious solution of deleting the existing file from a repository will break users who have followed best practices and pinned to a specific version of the project."

> …"new projects may be pulling down this known broken version, but if they do anything to prevent that they'll break projects that are already using it."

Yank lets projects "mitigat[e] the worst of the breakage while still keeping things working for projects who have otherwise worked around or didn't hit the underlying issues."

**Mechanism** — a flag in the simple index, bytes untouched:

> "Links in the simple repository **MAY** have a `data-yanked` attribute which may have no value, or may have an arbitrary string as a value. The presence of a `data-yanked` attribute **SHOULD** be interpreted as indicating that the file pointed to by this particular link has been 'Yanked'."

The attribute value is the yank reason; "Tools that process the simple repository API **MAY** surface this string to end users."

**Installer semantics**, verbatim:

> "An installer **MUST** ignore yanked releases, if the selection constraints can be satisfied with a non-yanked version."

Yanked files may still be used when they "are the only file that matches a version specifier that 'pins' to an exact version using either `==` (without any modifiers that make it a range, such as `.*`) or `===`", and "an installer **SHOULD** emit a warning when it does decide to install a yanked file."

pip implements exactly this: [`src/pip/_internal/resolution/resolvelib/factory.py`](https://github.com/pypa/pip/blob/main/src/pip/_internal/resolution/resolvelib/factory.py) skips yanked candidates unless `all_yanked and pinned` (its `is_pinned` accepts `===` and non-`.*` `==`), [`package_finder.py`](https://github.com/pypa/pip/blob/main/src/pip/_internal/index/package_finder.py) sorts yanked links below everything (`yank_value = -1 * int(link.is_yanked)`), and the install-time warning in [`resolution/resolvelib/resolver.py`](https://github.com/pypa/pip/blob/main/src/pip/_internal/resolution/resolvelib/resolver.py) reads:

> "The candidate selected for download or install is a yanked version: {name!r} candidate (version {version} at {link})\nReason for being yanked: {reason}"

PyPI's own gloss ([pypi.org/help](https://pypi.org/help/)): "A yanked release is a release that is always ignored by an installer, unless it is the only release that matches a version specifier (using either `==` or `===`)."

### Deletion — still fully available to authors

Unlike every other registry here except old npm, PyPI **still permits outright author deletion** with no window and no usage conditions ([pypi.org/help](https://pypi.org/help/)):

> "Deletion of a project, release or file on PyPI is permanent and irreversible, without exception."

> "Deletion of a project makes it uninstallable, and releases the project name for use by any other PyPI user. Deleted files cannot be re-uploaded." … "PyPI does not allow for a filename to be reused, even once a project has been deleted and recreated."

So: filename coordinates are tombstoned forever, but the *project name* is immediately free for anyone — a sharper squatting seam than npm's 24-hour block.

**Trajectory:** [PEP 763 — Limiting deletions on PyPI](https://peps.python.org/pep-0763/) (Woodruff & Challande, created 2024-10-24) proposed npm-style windowing:

> "A project, release, or file may only be deleted within 72 hours of when it is uploaded to the index. From this point, users may only use the 'yank' mechanism specified by PEP 592."

(with an exception for pre-release-only files, and admin override). Its motivation catalogs real deletion incidents (`atomicwrites`, `codecov`, `PySimpleGUI`) and argues deletions "present a greater risk and detriment to the Python ecosystem than a benefit." The PEP was **Withdrawn** on 2025-09-22 — on venue grounds, not merits: "a PEP is not necessarily the appropriate venue for changes to PyPI's deletion policy, as PyPI's usage policies are not presently (or necessarily should) be part of the PEP process." As of 2026-07-11 unrestricted author deletion remains live. PyPI did add a softer signal, **project archival** ([pypi.org/help](https://pypi.org/help/)): "Archived projects are publicly visible and can still be resolved from the index by default, unlike deleted or yanked releases. An archived project cannot make new releases and will not appear in PyPI's search results."

## 4. Go modules — advisory `retract` over effectively immutable storage

### Immutability substrate

Once a version is fetched through [proxy.golang.org](https://proxy.golang.org/), it is cached and its hash is in the append-only checksum database. The proxy's FAQ ("I removed a bad release from my repository but it still appears in the mirror, what should I do?"), verbatim:

> "Whenever possible, the mirror aims to cache content in order to avoid breaking builds for people that depend on your package, so this bad release may still be available in the mirror even if it is not available at the origin. The same situation applies if you delete your entire repository. We suggest creating a new version and encouraging people to use that one instead.
>
> If you would like to hide versions of a module from the `go` command, as well as pkg.go.dev, you should retract them."

And on the checksum side: "The checksums will still remain in the checksum database regardless of whether or not they have become unavailable in the mirror." ([proxy.golang.org](https://proxy.golang.org/)). The checksum database ([sum.golang.org](https://sum.golang.org/): "an auditable checksum database which will be used by the go command to authenticate modules") "is built on a Transparent Log (or 'Merkle tree') of hashes backed by Trillian… tamper proof and has properties that don't allow for misbehavior to go undetected"; "Even the author of a module can't move their tags around or otherwise change the bits associated with a specific version from one day to the next without the change being detected." ([Go blog, "Module Mirror and Checksum Database Launched"](https://go.dev/blog/module-mirror-launch), Katie Hockman, 2019-08-29). The only removal path the proxy page documents is reporting malicious content to security@golang.org.

### `retract` — advisory metadata in the module's own go.mod

[go.dev/ref/mod#go-mod-file-retract](https://go.dev/ref/mod#go-mod-file-retract):

> "A `retract` directive indicates that a version or range of versions of the module defined by `go.mod` should not be depended upon. A `retract` directive is useful when a version was published prematurely or a severe problem was discovered after the version was published."

Publication is by shipping a **new** version:

> "To retract a version, a module author should add a `retract` directive to `go.mod`, then publish a new version containing that directive. The new version must be higher than other release or pre-release versions; that is, the `@latest` version query should resolve to the new version before retractions are considered."

Client behavior:

> "Retracted versions are excluded when resolving version queries like `@>=v1.2.3` or `@latest`."

> "`go get` prints a warning for each retracted version or deprecated module it finds."

> "Retracted versions are hidden from the version list printed by `go list -m -versions` unless the `-retracted` flag is used."

> "When a module version is retracted, users will not upgrade to it automatically using `go get`, `go mod tidy`, or other commands."

And, explicitly, nothing changes for the already-fetched:

> "Retracted versions should remain available in version control repositories and on module proxies to ensure that builds that depend on them are not broken."

> "Builds that depend on retracted versions should continue to work, but users will be notified of retractions when they check for updates with `go list -m -u` or update a related module with `go get`."

**Propagation quirk worth noting:** the retraction signal lives in the *latest* version's go.mod, not in a registry-side flag. A client only learns of a retraction when it fetches fresh metadata for `@latest`; and a compromised or unwilling author can never retract *below* their highest version without publishing above it. Retraction is purely a warning + resolver-exclusion — it removes nothing and cannot stop a determined or already-pinned consumer.

## 5. NuGet — unlist (search-hide) with permanent installability

[Deleting NuGet Packages from nuget.org](https://learn.microsoft.com/en-us/nuget/nuget-org/policies/deleting-packages), verbatim:

> "nuget.org does not support permanent deletion of packages. Doing so would break every project depending on the availability of the package, especially with build workflows that involve package restore."

> "nuget.org does support unlisting a package… Unlisted packages don't appear on nuget.org or in the Visual Studio UI, and do not appear in search results. Unlisted packages, however, can still be downloaded and installed by using an exact version number, which supports package restore."

Documented leaks in the hiding:

> "unlisted packages may still be discovered in the following specific scenarios:
> - Package restore using floating versions (for example, `1.0.0-*`), if the latest available package matching the version or dependency constraints is an unlisted package.
> - Replication of packages through the catalog (as the catalog also contains unlisted packages)."

Exceptions:

> "In exceptional situations such as copyright infringement and potentially harmful content, packages can be deleted manually by the NuGet team."

plus a "Prohibited use" list (malware, harm, infringement, illegal content, ID squatting, ToS violations) under which packages "will be immediately removed without discussion." The same page points to package **deprecation** ("in case you can't delete a package version") as the messaging channel. There is no time or usage window anywhere in the policy: unlist is available forever, delete is never available to authors.

## 6. Maven Central — no retraction at all

[Central FAQ, "Can I change, modify, delete, remove, or update a component on Central?"](https://central.sonatype.org/faq/can-i-change-a-component/):

> "Once a component has been released and published to the Central Repository, it cannot be altered."

Rationale (build-tool interaction model — download once, never re-check):

> "If release repositories were constantly changing, the tools would have to start periodically checking for a newer artifact. This would exponentially increase traffic to Central, affect everyone's builds, and break a core feature of a build tool used by millions."

The [immutability requirement page](https://central.sonatype.org/publish/requirements/immutability/) states it flatly:

> "We do not remove or modify components once they are publicly available."

> "When a project includes a specific version of a component as a dependency, there is an inherent expectation that end-users will be able to build that project in a repeatable, reliable manner" … "Maven Central will be able to provide every dependency exactly as they were originally published."

Neither page documents *any* exception process or removal request path — the fix for a bad artifact is "publish a new version." Maven Central also has no registry-level deprecation/yank flag; adverse signal travels out-of-band (advisory databases, `maven-metadata.xml` latest-version pointers).

## 7. Cross-cutting extraction

### 7.1 Comparison table

| Registry | Mechanism | Window / conditions (exact) | Bytes deleted? | Already-fetched installers see | New resolutions see | Who can trigger | Escape hatch for pinned users |
|---|---|---|---|---|---|---|---|
| **npm** | `unpublish` (destructive) | ≤72 h: free if "no other packages… depend on your package"; >72 h: all of "no other packages… depend on it", "less than 300 downloads over the last week", "a single owner/maintainer" ([policy](https://docs.npmjs.com/policies/unpublish/)) | **Yes** | Tarball 404s; lockfile installs break on next cold fetch | Version gone from packument; name free after 24 h; `package@version` never reusable | Owner (within window); npm support/security beyond | None — bytes are gone |
| **npm** | `deprecate` | None — anytime | No | Warning "every time the package is downloaded" | Same warning | Owner | n/a (nothing removed) |
| **crates.io** | `cargo yank` | None — anytime, reversible (`--undo`) | No — "does not delete any data"; `cksum` stays in index, `yanked: true` flips | Existing Cargo.lock resolves unchanged; publish/`--locked` warns "package … in Cargo.lock is yanked" | Excluded from fresh resolution; `= x.y.z` pins **error** | Owner | Existing lockfile; `cargo update --precise <yanked>` ("not recommended") |
| **crates.io** | owner delete (2025) | "not depended upon by any other crate" AND (<72 h published OR ("single owner" AND "<1000 times for each month it has been published")) ([delete page](https://github.com/rust-lang/crates.io/blob/main/svelte/src/routes/crates/%5Bcrate_id%5D/delete/%2Bpage.svelte)) | **Yes** | Downloads break | Crate gone | Owner (team for policy violations, permanent) | None |
| **PyPI** | yank (PEP 592) | None — anytime, reversible | No — `data-yanked` flag on the simple-index link | Nothing changes for installed envs; `==`/`===` pins still install, with pip warning "The candidate selected… is a yanked version" | "MUST ignore yanked releases" unless only pinned match | Maintainer | `==`/`===` pin (by spec) |
| **PyPI** | delete | **None — unrestricted** ("permanent and irreversible, without exception"); PEP 763's 72 h window was Withdrawn | **Yes** | Files 404; hash-pinned installs break | Project name immediately free to anyone; filenames never reusable | Maintainer; admins | None |
| **Go modules** | `retract` directive | None — anytime, via publishing a **new higher version** whose go.mod carries `retract` | No — proxy keeps serving; sumdb append-only | Nothing — "Builds that depend on retracted versions should continue to work"; warnings on `go get`/`go list -m -u` | `@latest` and range queries exclude retracted; warning if selected explicitly | Module author (only by publishing above) | Everything still works; explicit `@version` fetch succeeds with warning |
| **NuGet** | unlist | None — anytime, reversible | No | Nothing — exact-version install/restore works "forever" | Hidden from search/UI; still reachable via floating versions & catalog | Owner (delete: NuGet team only, "exceptional situations") | Exact version reference |
| **Maven Central** | — none — | "cannot be altered"; "We do not remove or modify components once they are publicly available" | No | Nothing | Nothing — no flag exists | Nobody (no documented process) | n/a |

### 7.2 Time-based vs usage-based bounds — and the negative result

- **npm** is the only registry whose retraction conditions include *usage*: ">72 h" requires "no other packages in the npm Public Registry depend on it", "less than 300 downloads over the last week", "a single owner/maintainer" ([policy](https://docs.npmjs.com/policies/unpublish/)). Note both usage measures are *current-state* checks (dependents now, trailing-7-day downloads), not cumulative counters.
- **crates.io** owner-deletion is the nearest second: a hard no-reverse-dependencies gate plus "downloaded less than 1000 times for each month it has been published" — a **rate-normalized** (per-month-of-age) download threshold, again not a raw cumulative cap ([current delete page](https://github.com/rust-lang/crates.io/blob/main/svelte/src/routes/crates/%5Bcrate_id%5D/delete/%2Bpage.svelte); RFC 3660 launched at 100, blog announced 500).
- **Negative result, stated explicitly:** *no surveyed registry uses a cumulative download count as a hard bound on the retraction window* the way Sentinel plans (retraction allowed only while total downloads < N). npm uses trailing-week downloads as an eligibility condition; crates.io uses downloads-per-month-published; PyPI, Go, NuGet, and Maven use no usage measure at all. The combination "time bound AND cumulative-download bound, then immutability" has no primary-source precedent found in this survey.
- Adjacent prior art in the *opposite* direction: Cargo's accepted min-publish-age RFC 3923 (delaying *availability* of new publishes rather than bounding retraction; tracking: [rust-lang/cargo#17009](https://github.com/rust-lang/cargo/issues/17009)) — a time window between publish and consumability, which interacts with yank (its discussions consider the case where all old-enough versions are yanked).

### 7.3 How mirrors / caches / offline corpora learn of retraction

| Ecosystem | Propagation channel | Notes / failure mode |
|---|---|---|
| npm unpublish | Packument change (version disappears) + tarball 404 | Mirrors learn by diffing/refetching packuments; caches holding the tarball diverge silently from the registry. Left-pad: everything downstream of the packument broke at once, and only npm's backup restore ("un-un-publish") ended it ([postmortem](https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm)). |
| npm deprecate | Packument field (`deprecated`) | Signal-only; mirrors that strip fields lose it. |
| crates.io yank | Index flag flip: "The JSON objects should not be modified after they are added except for the `yanked` field whose value may change at any time." ([index format](https://doc.rust-lang.org/cargo/reference/registry-index.html)) | Clean, diffable, checksum-preserving. Divergence mode is *client-side*: a cached/committed Cargo.lock keeps a yanked version alive indefinitely — surfacing as late warnings (e.g. `cargo install --locked` warning on a long-yanked dep, [starship#6494](https://github.com/starship/starship/issues/6494)). |
| PyPI yank | `data-yanked` attribute on the simple-index link (PEP 592) | Same shape as crates. PyPI **delete** propagates as plain 404 — the PEP 763 motivation lists `atomicwrites`, `codecov`, `PySimpleGUI` as deletion disruptions. |
| Go retract | **A new version's go.mod** — no registry-side flag at all | Clients must fetch `@latest` metadata to ever see it; proxies keep serving retracted bytes by design ("this bad release may still be available in the mirror even if it is not available at the origin", [proxy.golang.org](https://proxy.golang.org/)). "Retraction is just a warning": it cannot remove a malicious version, and it cannot exist at all unless the author can publish a higher version. |
| NuGet unlist | Listed flag; but "the catalog also contains unlisted packages" and floating versions can still select them ([policy](https://learn.microsoft.com/en-us/nuget/nuget-org/policies/deleting-packages)) | Documented incomplete hiding: replication consumers see everything. |
| Maven Central | Nothing — no mechanism exists | Adverse signal must travel out-of-band (CVE databases, project announcements). |

### 7.4 The stability-vs-maintainer-control spectrum

From most maintainer control to most consumer stability, with each step's primary-source anchor:

1. **Full delete, anytime** — npm pre-2016 (no policy; see [postmortem](https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm)) and **PyPI delete today** ("permanent and irreversible, without exception", name immediately reusable). Failure mode demonstrated: left-pad; atomicwrites/codecov/PySimpleGUI.
2. **Windowed delete** — current npm (72 h, then no-dependents + <300 dl/week + single owner) and crates.io owner-delete (no dependents + (72 h OR single-owner + <1000 dl/month-published)); PEP 763 proposed exactly this for PyPI and was withdrawn on process grounds.
3. **Metadata-only yank/unlist over retained bytes** — crates.io yank (index flag, `--undo`, `--precise` override), PyPI yank (PEP 592: MUST-ignore unless `==`-pinned, SHOULD-warn), NuGet unlist (exact-version installable forever). Consumer breakage bounded to *fresh* resolutions; pinned users keep working.
4. **Advisory retract over immutable storage** — Go: append-only sumdb + caching proxy; retraction is a warning and `@latest` exclusion, removal essentially only for legal/malicious content via a manual process.
5. **No retraction** — Maven Central: "Once a component has been released and published to the Central Repository, it cannot be altered."

Every ecosystem that started at (1) has moved right after an incident (npm after left-pad; PyPI attempted via PEP 763); the one that started at (5) has stayed there and cites repeatable builds as the reason; crates.io is the only one observed moving *left* (adding windowed delete to a previously yank-only registry), and it did so with npm's window shape as its explicit reference point (RFC 3660 cites npm's 24-hour name-block as prior art for its open name-reuse question).

## 8. Confidence & gaps

- **npm 24 h → 72 h transition undated.** The 2016 blog set 24 h + support escalation; today's policy is 72 h + mechanical conditions. No first-party dated announcement of the change was found. Current policy text confirmed as of 2026-07-11.
- **npm "<300 downloads over the last week"** — confirmed verbatim from [docs.npmjs.com/policies/unpublish](https://docs.npmjs.com/policies/unpublish/) today; historical values not traced.
- **crates.io download-threshold drift (100 → 500 → 1000)** is confirmed across RFC 3660 → Feb-2025 blog → current frontend source, but no first-party changelog entry explaining the bumps was found; the rendered crates.io policies page is JS-only, so the frontend source file is cited as the closest primary text.
- **"RFC 3016" on yanked diagnostics: not confirmed.** No Rust RFC by that number concerning yank diagnostics was found; cargo's yanked-version warnings are documented only via the cargo changelog (1.37, [#6840](https://github.com/rust-lang/cargo/pull/6840)) and current source. Treated as a negative result.
- **Maven Central exceptions:** the FAQ and immutability pages document *no* exception process at all. Whether Sonatype removes malware/legal-takedown artifacts in practice is not confirmable from those pages and is left unclaimed.
- **proxy.golang.org legal-takedown process:** the page documents only security@golang.org for malicious content; no formal legal/PII removal request process is described on it. Any statement that Go removals are "legal/security takedowns via a request process" beyond that quote would exceed the primary source.
- **Left-pad quantitative details** ("hundreds of failures per minute", ~2.5 hours, 273 packages) are as reported in npm's own postmortem; no independent verification attempted.
- **NuGet**: policy page last substantively dated 2018 (page metadata shows updates through 2025); semantics re-confirmed from the live page today.
- **PyPI deletion restrictions:** as of 2026-07-11, none are in force (PEP 763 Withdrawn 2025-09-22, venue grounds); if PyPI later adopts limits administratively it will not necessarily appear in a PEP — worth re-checking before the downstream design ticket relies on this.

# ADR-0056: Security audit hardening

**Status:** Accepted
**Date:** 2026-11-20
**Supersedes (in part, without editing them):**
ADR-0039 (the claim that type-7 entries are never surfaced as `entry` events),
ADR-0049 (the rule that a file with a non-`text` sniff is never retained),
ADR-0046 (organization-label matching as Tier-1 evidence), and the `INIT_CWD`
root detection described in ADR-0019 and ADR-0038.
**Extends:** ADR-0010, ADR-0015, ADR-0017, ADR-0021, ADR-0022, ADR-0025,
ADR-0036, ADR-0037, ADR-0042, ADR-0043, ADR-0045 to ADR-0048

## Context

A read-only security audit of the tarball extractor, rules, provenance and
lockfile code, the proxy, the sandbox, enforced installs, the claim steward,
the GitHub Action and the CLI found gaps where an attacker-controlled package,
lockfile, header or request body reached a trust decision. Each finding was
reproduced with a hermetic test before it was fixed. This ADR records the
decisions. Findings that stayed as documented trade-offs are listed at the end.

## Decisions

### Tarball extraction

1. **Type-7 entries are scanned.** node-tar reports typeflag 7 as
   `ContiguousFile`, and npm installs it as a normal file. Extraction now
   accepts every entry type that ends in `File`. ADR-0039 was wrong that these
   bodies never surface.
2. **A mismatched text-extension file is also scanned.** A `.js` file whose
   first bytes look binary or compressed is still reported as
   `content-mismatch`. It is now also retained as a text `PackageFile` when its
   bytes decode as valid UTF-8 with no NUL byte and fit the size cap, so the
   rules see it. `MZ:` and `BZh:` are valid JavaScript labels, so a magic-byte
   check alone hid real code. Real binaries are still not retained. This
   replaces the "never retained" rule in ADR-0049.
3. **Entry paths are normalized like npm.** The first path segment is replaced
   by `package`, trailing separators are dropped, the rest is normalized as a
   posix path, and `..` is rejected. A backslash is a filename character on POSIX
   and a separator on Windows, so the root-manifest count uses both readings,
   and a file whose two readings differ is retained under both paths. When a
   Windows-reading path collides with another retained path, `manifest-confusion`
   fires. Root manifests are counted
   case-insensitively after normalization. A new synthesized finding,
   `manifest-confusion` (critical, category `metadata`), fires when there is
   more than one root manifest, a case-variant manifest, or a root manifest too
   large to scan. It blocks under `DEFAULT_POLICY`. Zero manifests add no
   finding, so there is no new tarball-side bypass.
4. **Nested compression is refused.** The tar parser auto-detects gzip and
   zstd, so gzip(gzip(tar)) and raw zstd decompressed past `maxUnpacked`
   uncounted. A compressed signature in the first bytes the parser sees now sets
   `truncated`, which reports `resource-abuse`.
5. **Extension-less text files are retained** up to 2 MiB. `install-scripts`
   resolves every command token that names a retained package file (`node
   setup`, `sh build.sh`) and scans it. Tokens that name docs or data
   (`README`, `.md`, `.json`) are skipped.

### Scoring inputs

6. **Registry signatures with no matching trusted keyid count as `unsigned`**
   (weight 4, low), not `unknown` (weight 0). A list of signatures that match no
   trusted key is no better than none. Key expiry is not checked: it needs the
   publish time, and the wall clock never enters scoring (invariant 1).
7. **Policy globs use a linear wildcard matcher.** The old `a*b*c` to
   `^a.*b.*c$` translation backtracked. `*` now also matches line terminators.
8. **Rules fail soft on hostile input.** Non-string lifecycle hooks are
   skipped. The `native-payload-loader` `exports` walk stops at depth 32. A
   stack overflow in the loader-chain AST walk maps to `parseFailed`. Quadratic
   regexes are bounded or replaced by linear scans. `install-scripts`
   parses each simple command (split on `&&`, `||`, `;`, `|`, `&`, newline),
   skips `VAR=value` and wrapper words, and scans the files that are executed:
   an interpreter's script operand (and `-r`/`--import` values), or the command
   word itself. Every operand with a code extension (`.js`, `.cjs`, `.mjs`,
   `.ts`, `.sh`, `.py`, `.pl`, `.rb`) is also scanned, so an unknown wrapper
   (`sudo`, `timeout`, `xargs`) cannot hide a script. Inline-code flags are per
   interpreter (`-c` for shells, `-e`/`-p` for node, and so on), so `sh -e x.sh`
   still scans `x.sh`, and shell `-c` code is parsed as a command line (depth
   3). Quoted command words are unquoted first. `.py`, `.pl` and `.rb` files
   are retained. Data arguments such as `README.md` are not scanned. There
   is no token-count cap, so padding cannot hide `node evil`. Residual: the
   command split ignores shell quoting. Base64 markers match any case and `base64url`, since Node
   accepts both, in the obfuscation rule, the loader fallback and the
   loader-chain decode step. A template literal without expressions,
   ``require(`fs`)``, is a static binding.

### Provenance and lockfiles

9. **Provenance identity comes from the certificate.** `sourceRepository` and
   `ref` are read from the Fulcio leaf certificate extensions (OID
   1.3.6.1.4.1.57264.1.12 and .14) with a small DER walker, never from the SLSA
   predicate, which any Sigstore signer writes. They are `null` when the
   certificate lacks them, with no predicate fallback. `builder` and `commit`
   stay predicate-sourced. A trusted-publisher entry authorizes only when it
   constrains `repository` or `workflowRef` and those match, so a builder match
   alone never authorizes. Residual: a signed policy identity requirement that
   constrains only `builder` can be met by a signer-written builder.
10. **Non-registry lockfile entries are flagged.** `Coordinate` gains
    `nonRegistry`, the raw `resolved` spec, set when the entry is not an http(s)
    `/-/<file>.tgz` registry tarball (git, `github:`, other tarball URLs). The
    flag is sticky when duplicate `name@version` entries merge. `POST
    /-/audit-tree` returns a `block` row for such a coordinate and fetches
    nothing; the dedupe key includes the marker so a git row never shares a
    registry row's verdict. Yarn berry `workspace`, `patch`, `link`, `portal`,
    `file` and `exec` entries and pnpm directory entries are skipped, not
    flagged. A patch overlay's registry base is its own entry and is audited;
    the patch itself is not. A registry coordinate also needs an integrity pin
    with a known algorithm (yarn v1 `#<sha1>` fragments count): without one, npm
    would install unverified bytes from whatever host the lockfile names, so the
    entry is flagged. Conflicting pins for one `name@version` are flagged.
    `audit-tree` checks each distinct pin against the served bytes (sha1,
    sha256, sha384, sha512, every token must match), and a claim with an
    unknown algorithm blocks instead of being skipped. A lockfile name outside
    the npm grammar is reported as `<unparsed>` and a non-plain version as
    `0.0.0`, both flagged, so no URL text reaches the output. The block row
    names only the source kind (git, url, other), never the raw resolution,
    which can carry credentials.

### Proxy

11. **`SENTINEL_POLICY` must be exactly `observe` or `block`,** else FATAL. A
    typo such as `Block` used to serve blocked packages.
12. **The proxy binds `127.0.0.1` by default.** `SENTINEL_HOST` overrides it
    and an empty value is FATAL. Network deployments must set it. This breaks
    deployments that relied on all interfaces; the project is pre-1.0.
13. **Compatibility routes do not forward client credentials.** `authorization`,
    `cookie` and `npm-otp` are dropped before the upstream request on every
    compatibility route, web login included: npm attaches the token it has for
    this registry URL, which is a Sentinel token. Bodies are capped at 8 MiB
    (npm posts the full tree to `advisories/bulk`) and the routes sit behind the
    opt-in rate gate. An oversized upload is drained (bounded) before the 413 is
    sent, so the client receives it.
14. **Open mode no longer exposes import and retraction.** With
    `SENTINEL_AUTH_PUBKEY` unset, `POST /-/registry/import` and
    `POST /-/retractions` require a publish token, as publish does. With no
    publish tokens configured they always return 401. With auth enabled they
    still require the `operator` role.
15. **`AuditStore` is bounded.** It keeps at most 20,000 entries in memory and
    evicts the oldest first. Approvals and violations for an evicted coordinate
    answer "audit first", which is the existing behavior for an unknown
    coordinate. There is no env var. Reports carry `engine.revision`
    (`AUDIT_REVISION`, bumped whenever rule semantics change). The store skips
    persisted reports whose engine version or revision differs, and the native
    serve path re-audits a stored publication with a stale audit from the stored
    bytes, without rewriting the publication record. Only imported versions
    reuse the registry signatures kept in their manifest; a publisher's
    version is re-audited with none, as at publish time.
    History import now stores the verified provenance bundles. An imported
    version stored before that carries its import-time provenance result into
    the re-audit (`runAudit` input `provenanceCarryOver`, set only by the proxy
    and only for imported versions; it was verified against the same bytes).
    Writes to the store file are debounced (about 500 ms) and flushed on exit,
    `SIGTERM` and `SIGINT`.

### Sandbox and enforced installs

16. **The Seatbelt profile is passed inline** (`sandbox-exec -p`). The profile
    file under the OS temp dir was inside the write floor, so a lingering
    sandboxed process could rewrite the next run's profile.
17. **bwrap isolates pid, session and local IPC.** Every run adds
    `--unshare-pid --new-session`. `--die-with-parent` is not used: its
    `PR_SET_PDEATHSIG` is tied to the forking thread and intermittently killed
    runs at start, and the pid namespace already ends orphans with the command.
    Residual, unchanged from before: if Sentinel is killed mid-run, the
    sandboxed command still runs to completion inside the sandbox. Local IPC masks apply
    whether or not network is approved, because `--unshare-net` does not cover
    pathname unix sockets: the user session bus under `/run/user/<uid>`, the
    docker, containerd, podman and crio sockets, the system dbus socket, and
    `/tmp/.X11-unix` and `/tmp/ssh-*` when present. Each mask is
    existence-guarded and is lifted only by an explicit filesystem grant. When
    the working directory, project root or `$HOME` sits under a directory that
    would be masked, the run is refused rather than left unmasked. Residual:
    abstract unix sockets stay reachable when `network` is approved, because
    there is no network namespace then.
18. **More exec carve-outs.** `SENSITIVE_EXECUTABLES` adds `launchctl`, `open`,
    `shortcuts` and `automator` (hand work to a process outside the sandbox on
    macOS) and `systemd-run`, `busctl`, `dbus-send` and `gdbus` (the Linux
    equivalents). The carve-out matches paths, not mach services: the profile
    does not deny LaunchServices mach lookups, and macOS kills a copied
    `launchctl` itself.
19. **The node-gyp header caches are read-only.** `~/.node-gyp` and
    `~/.cache/node-gyp` leave the write floor, because a shared writable cache
    lets one package plant headers a later build trusts. With a `network`
    approval, `npm_config_devdir` points at a per-run directory outside every
    write floor; without one, a cold-cache native build fails.
20. **Path edge cases.** A project root of `/` never widens read or exec rules.
    `cwd` and project root are resolved to their real paths before use, and a
    working directory that resolves to `/` (including through a symlink) is
    refused on both backends. `npm_config_*`
    values that contain URL credentials are scrubbed. Violation `target`,
    `deniedResource` and `stderrExcerpt` are stripped of control characters.
21. **Enforced installs bind to a trusted root and to the audited bytes.**
    `sentinel install --enforce` sets `SENTINEL_ROOT` to the realpath of the
    install cwd. It is not user-configurable. Root detection compares against it
    and fails closed when it is missing. `INIT_CWD` is no longer trusted,
    because a nested npm (a git dependency's `prepare`) resets it. A dependency
    script runs only when `npm_package_integrity` matches the audited integrity,
    compared per algorithm, and `npm_config_user_agent` names npm 7 or newer.
    npm 7 and later set that variable from the lockfile node and export only
    name, version, config, engines and bin from package.json (npm RFC 183);
    npm 6 exports every field, so the package could set its own integrity. Residual: a package npm records only as sha1 fails closed. A git
    dependency with a `prepare` script fails closed too: npm prepares it in a
    nested install whose scripts are neither the root nor integrity-bound.
    Residual: on macOS a sandboxed process can outlive its script, because there
    is no process-group kill.

### Claim steward

22. **Tier 1 needs a homepage or repository host at or under the claimed
    domain.** A same-named GitHub or GitLab organization no longer counts. Such
    claims land in Tier 2 (evidence plus the 30-day timelock). This replaces the
    organization-label evidence in ADR-0046.
23. **Challenges expire 30 days after issue** for verify, approve, transfer,
    renew and rule-dispute. The tier is recomputed at approval from a fresh
    upstream lookup.
24. **The state machine has fewer gaps.** A transfer needs an active claim with
    no pending change, and a pending transfer materializes only while the claim
    is active. A dispute survives expiry and domain-change freezes; only a
    dispute ruling clears it. Renewal refuses a disputed claim and needs a
    challenge verified after the current proof.
25. **Transfer signatures bind the claim's current challenge id,** so an old
    signature cannot replay after a renewal or transfer. Every proof is single
    use: `verifiedAt` never changes once set, and a challenge adopted by an
    approval, transfer, ruling or renewal is consumed and refused afterwards.
    State written before proof tracking spends every verified challenge on
    load, so in-flight approvals, transfers, renewals and rulings need a fresh
    challenge after the upgrade.
26. **Request bodies are validated.** `evidenceRef` must be a non-empty string.
    Application fields are copied explicitly, so a body-supplied `verifiedAt`
    can no longer skip DNS.
27. **The steward binds `127.0.0.1` by default.** `SENTINEL_STEWARD_HOST`
    overrides it and an empty value is FATAL.

Public API changes: `ClaimSteward.approve` is async, and `signTransferRequest`
and `transferRequestBytes` take `currentChallengeId`.

### Action and CLI

28. The PR comment is reused only when the marker is on a comment authored by
    `github-actions[bot]`, and comment lists are paginated.
29. Workflow-command data (`%`, CR, LF) is escaped, including fatal errors.
    No annotation properties are emitted. PR comment Markdown
    neutralizes backticks, `<`, `[`, `]` and `@`.
30. The CLI passes package-controlled text through `sanitizeTerminal()`, and
    `run-scripts` resolves its directory argument.

### Release workflow

31. The publish job keeps only `contents: read` and `id-token: write`. Installing
    the published packages in a clean project moved to a
    `verify-registry-install` job with `permissions: {}`. Creating the GitHub
    release moved to a `github-release` job with `contents: write`. `ci.yml`
    has a read-only token. Third-party install code no longer runs with a
    token that can publish or write.

### Dependencies

32. **Production advisories are fixed.** `npm audit fix` updated the transitive
    packages, and `@git-agentic/sentinel-mcp` moves from zod 3 to zod 4.6.7
    (GHSA-mrhx-c7xc-m3w5). The installed `@modelcontextprotocol/sdk` accepts
    `zod ^3.25 || ^4.0`, and the MCP source only uses `z.string()` and
    `.optional()`. `npm audit --omit=dev` reports no vulnerabilities.

## Consequences

- Several defaults are stricter: the proxy and steward bind loopback,
  `SENTINEL_POLICY` is validated, open-mode import and retraction are closed,
  and non-registry lockfile entries gate `audit-tree`.
- A tarball with two root manifests, or an unscannable one, now blocks.
- Sandboxed native builds without a `network` approval fail on a cold node-gyp
  cache.
- The `Coordinate` shape, `ClaimSteward.approve` and the transfer-signing
  helpers changed. Callers must update.
- A resolved registry entry without an integrity pin gates `audit-tree`,
  including yarn v1 files from private registries that record neither
  `integrity` nor a `#sha1` fragment. Yarn berry entries carry no SRI and are
  judged by their locator only.
- A version imported before this change keeps its verified provenance but
  loses the predicate-sourced `sourceRepository` and `ref`. Under a signed
  policy whose `provenanceIdentities` constrain `repository`, it now gets a
  critical finding, and re-import is refused once native history exists. The
  operator's remedy is a policy exception for that name (or relaxing the
  repository constraint) until a new release is published with provenance.
- Detection gaps (`npm run <name>` was closed in #85, by deliberate over-following:
  after `npm`, `pnpm`, `yarn` or `bun`, every word that names a defined script is followed with its
  `pre`/`post` scripts, each script once from a worklist, and its body gets the hook's inline-danger
  check; #86 closed `.`/`source` as interpreters, pipes into an interpreter, pathed wrappers,
  `tsx`/`ts-node`/`.ts` operands and `node <dir>`; #87 closed bare `-r`/`NODE_OPTIONS` specifiers,
  extension-less preload paths and bundled `node_modules/.bin` / `bin` commands, all resolved against the
  tarball only; `AUDIT_REVISION` is 6). #88 closed the walker overflow: the loader-chain walk is iterative (4,194,304-node safety bound,
  1,000 nested scopes; a truncation takes the strict fallback), so the loose overflow fallback serves only parser or walk stack overflows. Other rules still scan those
  files; only the lifecycle-script escalation is lost.

## Not changed

These were audited and kept as documented trade-offs: the steward rate limit
runs before authentication (threat model 6.2); download-window inflation in
retraction (6.4); open-mode reads.

## Rejected alternatives

- **Check registry key expiry in signature verification.** It needs the publish
  time, and the wall clock is banned from scoring. It would also downgrade every
  package signed only by npm's expired 2025 key.
- **Take `ref` from the predicate when the certificate lacks it.** That keeps the
  forgeable value reachable. Null fails closed.
- **Trust `INIT_CWD` plus a path check for the install root.** The variable is
  attacker-influenceable through nested npm.
- **Keep the Seatbelt profile file and tighten its directory.** Passing the
  profile inline removes the file.
- **Ship a general ASN.1 parser for the certificate.** Two extensions are needed,
  so a small TLV walker is enough and is tested on a real bundle.

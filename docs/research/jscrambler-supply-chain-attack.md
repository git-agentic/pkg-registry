# Jscrambler npm supply-chain attack (July 2026)

Research snapshot: 2026-07-12. This note distinguishes facts observable in npm's
registry metadata and published package bytes from researchers' malware analysis.
No package content is copied into this repository.

## Bottom line

An unauthorized publisher released five compromised versions of the established
`jscrambler` package on 2026-07-11: `8.14.0`, `8.16.0`, `8.17.0`, `8.18.0`, and
`8.20.0`. The first three used an npm `preinstall` hook to unpack and launch a
platform-specific native executable. The last two removed the install hook and
inlined the launcher into the package entry point and CLI, so importing the module
or running its command was enough and `--ignore-scripts` was not a defense.
[npm's live packument](https://registry.npmjs.org/jscrambler) records the exact
publication times, integrity hashes, file counts, sizes, scripts, and current
deprecation notices. [Socket's incident report](https://socket.dev/blog/jscrambler-supply-chain-attack)
documents its six-minute initial detection and the later delivery change.

Jscrambler says the attacker published with an npm publishing credential; it
revoked and rotated credentials and added controls around publishing. That is the
vendor's current finding, not something the package bytes alone prove.
[Jscrambler security advisory](https://jscrambler.com/blog/security-advisory-malicious-npm-package)

## Timeline and releases

The timestamps below are the registry's UTC `time` values. Clean and malicious
releases were interleaved, which matters for any rule that assumes a single bad
semver interval.

| Version | Published (UTC) | Observed status and trigger |
| --- | --- | --- |
| `8.13.0` | 2026-06-30 22:17:14 | Last pre-incident clean release; 17 files, 153,424 bytes unpacked |
| `8.14.0` | 2026-07-11 15:12:40 | Malicious; `preinstall: node dist/setup.js`; 19 files, 7,992,131 bytes; now deprecated as compromised |
| `8.15.0` | 2026-07-11 17:07:14 | Clean remediation release; 17 files, 153,512 bytes |
| `8.16.0` | 2026-07-11 17:26:20 | Malicious; same `preinstall` delivery; deprecated |
| `8.17.0` | 2026-07-11 17:41:21 | Malicious; same `preinstall` delivery; deprecated |
| `8.18.0` | 2026-07-11 17:46:55 | Malicious; launcher moved into runtime entry points; no install hook |
| `8.20.0` | 2026-07-11 17:53:25 | Malicious; runtime/CLI launcher; deprecated |
| `8.22.0` | 2026-07-11 18:12:51 | Current clean `latest` at research time; 17 files, 153,624 bytes |

Sources: [npm packument](https://registry.npmjs.org/jscrambler), package tarballs
linked by each version's `dist.tarball`, and independent byte-level release
comparison by [StepSecurity](https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary).
The live metadata currently does **not** mark `8.18.0` deprecated even though its
published bytes contain the same binary container and injected launcher reported
by Socket, StepSecurity, and JFrog; consumers must not equate “not deprecated”
with “clean.” Conversely, npm deprecation is only a warning: the deprecated
version records and tarball URLs still resolved on 2026-07-12, so consumers must
not equate “deprecated” with “uninstallable.”

## Mechanics established from the package bytes

Compared with `8.13.0`, `8.14.0` adds `dist/setup.js`, changes `package.json` to
run it during `preinstall`, and replaces the small legitimate `dist/intro.js`
artifact with an approximately 7.8 MB custom container. The loader:

1. recognizes the container by the five-byte header `1b 43 53 49 01`;
2. selects an entry for `linux`, `win32`, or `darwin`;
3. gzip-decompresses it into a randomly named hidden file under the OS temp
   directory;
4. makes non-Windows output executable; and
5. spawns it detached with ignored stdio, then calls `unref()`.

In `8.18.0` and `8.20.0`, equivalent loader code appears as an immediately
invoked function at the top of `dist/index.js` and `dist/bin/jscrambler.js`.
Those releases therefore evade an install-script-only gate. Socket also reports
that both declare a self-dependency on `jscrambler@^8.17.0`, potentially pulling
an earlier compromised release transitively.
[Socket technical analysis](https://socket.dev/blog/jscrambler-supply-chain-attack)

## Payload behavior and confidence

The native payload analysis is researcher-derived rather than directly asserted
by npm metadata. JFrog identifies it as an evolved IronWorm variant and reports
credential discovery (`NPM_TOKEN`, related environment names, and npmrc files),
token validation, target selection by download popularity, tarball infection,
and direct registry publication using stolen bearer tokens. It also reports
Linux, Windows, and macOS payload hashes plus two C2 IPs.
[JFrog Security Research](https://research.jfrog.com/post/ironworm-returns-rustier-than-ever/)

StepSecurity's dynamic monitoring observed outbound traffic to Tor Project hosts
and the same two IPs. Its static analysis found browser credential-store,
LevelDB, and BIP39-related capability indicators, supporting classification as a
credential and cryptocurrency-wallet stealer. These are strong independent
research findings, but attribution and the full payload behavior may evolve as
forensics continue.
[StepSecurity analysis](https://www.stepsecurity.io/blog/jscrambler-npm-package-publishes-malicious-preinstall-binary)

## Primary-source limitations

- npm's packument proves what was published and when, but registry signatures
  authenticate registry distribution, not publisher intent or source provenance.
- The package's public GitHub repository does not by itself establish that the
  malicious tarballs came from a reviewed source commit. The public tracking
  thread is [jscrambler/jscrambler#322](https://github.com/jscrambler/jscrambler/issues/322).
- Jscrambler's advisory is the first-party source for the unauthorized-credential
  claim and response actions; Socket, StepSecurity, and JFrog are the sources for
  detection timing and reverse-engineered payload behavior.
- The vendor advisory's affected-version list currently omits `8.18.0`; npm
  artifact inspection and all three independent research reports identify it as
  compromised. The vendor's statement that deprecated versions are unavailable
  through normal resolution should likewise be treated as its claim, because npm
  still served the corresponding metadata and tarballs at research time.

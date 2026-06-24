# Fixtures

Test packages for the Sentinel audit engine. `scripts/make-fixtures.ts`
(`npm run fixtures`) packs each version's `package/` directory into a real
npm-style `.tgz` under `.tarballs/` and writes `registry.json`, the document the
proxy's `LocalFixtureUpstream` serves.

```
benign/
  leftpad-lite/{1.0.0,1.0.1}/package/   clean utility; expected verdict: ALLOW (100/100)
malicious/
  color-stream/1.4.0/package/           clean prior release; ALLOW (100/100)
  color-stream/1.4.1/package/           trojaned patch;       BLOCK (0/100)
index.json                              declares versions + simulated signature status
registry.json                           GENERATED — do not edit by hand
.tarballs/                              GENERATED — packed tarballs (git-ignored)
```

## Safety

`malicious/color-stream/1.4.1/package/lib/build.js` is **inert synthetic test
data**, not real malware:

- It is never executed — the engine reads it as text and scores it.
- The exfiltration endpoint `198.51.100.23` is in the RFC 5737 TEST-NET-2 range
  reserved for documentation; it routes nowhere.
- It carries a `SYNTHETIC FIXTURE` header.

It reproduces the **event-stream / ua-parser-js** pattern (a clean package gains a
malicious `postinstall` in a patch release that harvests secrets, decodes an
obfuscated blob, `eval`s it, and exfiltrates) so the scanner can be proven to catch
the real-world signature. The actual historical payload (`flatmap-stream@0.1.1`)
was unpublished from npm, which is why we model it rather than download it.

**Never add live malware here.** New malicious fixtures must stay synthetic, inert,
header-marked, and use RFC 5737 IPs. See `CLAUDE.md`.

# Review Hardening Implementation Plan (#10, #11, #12)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land three P2/P3 review fixes — pin GitHub Action deps to commit SHAs (#10), surface unscanned executable-looking content as a finding (#11), and require an SLSA v1 predicate before provenance reads `verified` (#12).

**Architecture:** #10 is CI hygiene (pin `uses:` to SHAs + a CONTRIBUTING note). #11 has `extractTarball` (`@sentinel/core`) collect a bounded list of counted-but-unscanned executable-looking files, which `runAudit` turns into a LOW `unscanned-content` finding (MEDIUM when a native binary co-occurs with install scripts). #12 makes `verifyProvenance` (`@sentinel/core`) downgrade a cryptographically-valid attestation that carries no SLSA v1 predicate from `verified` to `unknown`.

**Tech Stack:** Node + TypeScript, npm workspaces (`core`), GitHub Actions YAML, `tar` 7, `node:test` + `tsx`.

## Global Constraints

- **Determinism (invariant #1):** the `unscanned-content` finding and the provenance status depend only on file list/sizes/predicate — no wall-clock. Same input ⇒ same verdict.
- **Weighting is by severity, not category:** LOW/MEDIUM findings contribute via `severityWeight` and never hard-block on their own. `"metadata"` is just a label.
- **`unscanned-content` is synthesized in `runAudit`** (like `resource-abuse`/`integrity-mismatch`) — it needs extract metadata, not `AuditInput`. Do NOT register it in `rules/index.ts`.
- **#12 reuses the existing `unknown` status** — no new `ProvenanceStatus` value. A bind mismatch or verification throw still maps to `invalid` (unchanged).
- **Executable-looking extension sets (exact):** large-code = `.js .mjs .cjs .ts .mts .cts .jsx .tsx` (over the 2 MB scan limit); native = `.node .wasm .so .dll .dylib .exe`. Unscanned list capped at **100** entries.
- **Pinned SHAs (resolved from the current tags — use verbatim):**
  - `actions/checkout` v4 → `34e114876b0b11c390a56381ad16ebd13914f8d5`
  - `actions/setup-node` v4 → `49933ea5288caeca8642d1e84afbd3f7d6820020`
  - `actions/upload-artifact` v4 → `ea165f8d65b6e75b540449e92b4886f43607fa02`
  - `actions/github-script` v7 → `f28e40c7f34bde8b3046d885e986cb6290c5673b`
  - `github/codeql-action` v3 (init + analyze share the repo SHA) → `02c5e83432fe5497fd85b873b6c9f16a8578e1d9`
- **Malicious fixture stays blocked; `npm run build` clean, `npm test` green.**
- **Delivery: one PR** on branch `review-hardening` off `main`, closing #10, #11, #12. ADR-0041 covers #11 + #12; #10 needs none.

---

### Task 1: Pin GitHub Action dependencies to commit SHAs (#10)

**Files:**
- Modify: `action.yml`, `.github/workflows/ci.yml`, `.github/workflows/codeql.yml`, `.github/workflows/sentinel-example.yml`
- Modify: `CONTRIBUTING.md`

**Interfaces:** none (CI/docs only).

- [ ] **Step 1: Create the branch**

```bash
git checkout main && git pull --ff-only && git checkout -b review-hardening
```

- [ ] **Step 2: Pin every third-party `uses:` to its SHA + `# vX.Y.Z` comment.** Make these exact replacements (leave `uses: ./` in sentinel-example.yml alone — it's a local path):

`action.yml`:
- `- uses: actions/setup-node@v4` → `- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4`
- `uses: actions/upload-artifact@v4` → `uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4`
- `uses: actions/github-script@v7` → `uses: actions/github-script@f28e40c7f34bde8b3046d885e986cb6290c5673b # v7`

`.github/workflows/ci.yml`:
- `- uses: actions/checkout@v4` → `- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4`
- `- uses: actions/setup-node@v4` → `- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4`

`.github/workflows/codeql.yml`:
- `- uses: actions/checkout@v4` → `- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4`
- `- uses: github/codeql-action/init@v3` → `- uses: github/codeql-action/init@02c5e83432fe5497fd85b873b6c9f16a8578e1d9 # v3`
- `- uses: github/codeql-action/analyze@v3` → `- uses: github/codeql-action/analyze@02c5e83432fe5497fd85b873b6c9f16a8578e1d9 # v3`

`.github/workflows/sentinel-example.yml`:
- `- uses: actions/checkout@v4` → `- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4`

- [ ] **Step 3: Add an "Updating pinned actions" note to `CONTRIBUTING.md`.** Add a short subsection (place it near the CI/definition-of-done material):

```markdown
## Updating pinned GitHub Actions

Action dependencies in `action.yml` and `.github/workflows/*` are pinned to full
commit SHAs (with a `# vX.Y.Z` comment) rather than mutable tags — a mutable tag
can be repointed after review, and this project is about supply-chain pinning.
When updating an action, change both the SHA and its version comment together,
after reviewing the release. Dependabot's `github-actions` ecosystem raises
SHA-pinned bump PRs and is the recommended maintenance path.
```

- [ ] **Step 4: Validate the YAML is well-formed**

```bash
node -e 'const y=require("yaml");const fs=require("fs");for (const f of ["action.yml",".github/workflows/ci.yml",".github/workflows/codeql.yml",".github/workflows/sentinel-example.yml"]) y.parse(fs.readFileSync(f,"utf8")); console.log("yaml ok")'
```
Expected: `yaml ok`. Also confirm no `@v` tag refs remain on third-party actions: `grep -rnE "uses: (actions|github)/[^@]+@v[0-9]" action.yml .github/workflows/` should print nothing.

- [ ] **Step 5: Commit**

```bash
git add action.yml .github/workflows/ CONTRIBUTING.md
git commit -m "ci: pin GitHub Action dependencies to commit SHAs (#10)"
```

---

### Task 2: Track unscanned executable-looking content in `extractTarball` (#11)

**Files:**
- Modify: `packages/core/src/extract.ts` (add `UnscannedEntry`, `ExtractResult.unscanned`, tracking in the entry handler)
- Test: `packages/core/test/extract.test.ts` (add cases)

**Interfaces:**
- Produces: `interface UnscannedEntry { path: string; size: number; kind: "large-code" | "native"; }`, exported. `ExtractResult` gains `unscanned: UnscannedEntry[]`. Constants `CODE_EXT`, `NATIVE_EXT`.

- [ ] **Step 1: Write the failing tests** — add to `packages/core/test/extract.test.ts` (reuse the file's existing `makeTgz` helper):

```ts
test("a large code file (>2MB .js) is tracked as unscanned large-code", async () => {
  const big = "x".repeat(3 * 1024 * 1024);
  const tgz = await makeTgz({ "package/index.js": "ok\n", "package/bundle.js": big });
  const r = await extractTarball(tgz);
  assert.equal(r.truncated, false);
  const u = r.unscanned.find((e) => e.path === "package/bundle.js");
  assert.ok(u && u.kind === "large-code", "large .js should be tracked as large-code");
  assert.ok(u.size >= 3 * 1024 * 1024);
});

test("a native binary is tracked as unscanned native", async () => {
  const tgz = await makeTgz({ "package/index.js": "ok\n", "package/addon.node": "\0\0binary" });
  const r = await extractTarball(tgz);
  const u = r.unscanned.find((e) => e.path === "package/addon.node");
  assert.ok(u && u.kind === "native", "*.node should be tracked as native");
});

test("a benign small package has no unscanned entries", async () => {
  const tgz = await makeTgz({ "package/index.js": "module.exports=1\n", "package/readme.md": "hi" });
  const r = await extractTarball(tgz);
  assert.deepEqual(r.unscanned, []);
});

test("a large non-executable file (>2MB .json) is NOT tracked", async () => {
  const bigJson = '{"a":"' + "x".repeat(3 * 1024 * 1024) + '"}';
  const tgz = await makeTgz({ "package/data.json": bigJson });
  const r = await extractTarball(tgz);
  assert.equal(r.unscanned.length, 0, "large .json is skipped but not executable-looking");
});
```

- [ ] **Step 2: Run — expect FAIL** (`unscanned` doesn't exist)

Run: `node --import tsx --test packages/core/test/extract.test.ts`
Expected: FAIL.

- [ ] **Step 3: Add the constants + type + field.** In `packages/core/src/extract.ts`, after the `TEXT_EXT` line add:

```ts
/** Executable code extensions (subset of TEXT_EXT); flagged as unscanned when over MAX_FILE_BYTES. */
const CODE_EXT = /\.(c?js|mjs|cjs|ts|mts|cts|jsx|tsx)$/i;
/** Native / binary executable extensions; never scanned, flagged as unscanned when present. */
const NATIVE_EXT = /\.(node|wasm|so|dll|dylib|exe)$/i;
/** Cap on the unscanned list to bound memory on a pathological many-binary tarball. */
const MAX_UNSCANNED = 100;

export interface UnscannedEntry {
  path: string;
  size: number;
  kind: "large-code" | "native";
}
```

And extend `ExtractResult`:

```ts
export interface ExtractResult {
  files: PackageFile[];
  unpackedSize: number;
  fileCount: number;
  /** True when a cap was hit and extraction was aborted early (ADR-0039). */
  truncated: boolean;
  /** Counted-but-unscanned executable-looking files: large code + native binaries (#11). */
  unscanned: UnscannedEntry[];
}
```

- [ ] **Step 4: Declare and populate the list.** In `extractTarball`, add `const unscanned: UnscannedEntry[] = [];` next to `const files: PackageFile[] = [];`. Then replace the `entry.on("end", …)` handler body with:

```ts
    entry.on("end", () => {
      if (truncated || !isFile) return;
      const path = normalize(entry.path);
      if (bytes <= MAX_FILE_BYTES && TEXT_EXT.test(path)) {
        const content = Buffer.concat(chunks).toString("utf8");
        const prev = baseline?.get(path);
        files.push({ path, content, size: bytes, changed: baseline ? prev !== content : false });
        return;
      }
      // Not scanned — record executable-looking content so the blind spot isn't silent (#11).
      if (unscanned.length < MAX_UNSCANNED) {
        if (bytes > MAX_FILE_BYTES && CODE_EXT.test(path)) unscanned.push({ path, size: bytes, kind: "large-code" });
        else if (NATIVE_EXT.test(path)) unscanned.push({ path, size: bytes, kind: "native" });
      }
    });
```

- [ ] **Step 5: Return the field.** Change the final `return { files, unpackedSize, fileCount, truncated };` to `return { files, unpackedSize, fileCount, truncated, unscanned };`.

- [ ] **Step 6: Run — expect PASS**

Run: `node --import tsx --test packages/core/test/extract.test.ts`
Expected: PASS (all, including the pre-existing bomb/completeness cases).

- [ ] **Step 7: Commit**

```bash
git add packages/core/src/extract.ts packages/core/test/extract.test.ts
git commit -m "feat(core): extractTarball tracks unscanned executable-looking files (large code + native)"
```

---

### Task 3: Synthesize the `unscanned-content` finding in `runAudit` (#11)

**Files:**
- Modify: `packages/core/src/audit.ts` (synthesize the finding next to `resource-abuse`)
- Test: `packages/core/test/audit.test.ts` (add cases)

**Interfaces:**
- Consumes: `ExtractResult.unscanned` (Task 2), `detectInstallScripts(files)` (already in `audit.ts`).
- Produces: a finding `{ ruleId: "unscanned-content", category: "metadata", severity: "low" | "medium", … }`. LOW normally; MEDIUM when a `native` entry is present AND install scripts run.

- [ ] **Step 1: Write the failing tests** — add to `packages/core/test/audit.test.ts` (reuse `makeTgz` and the `metaFor` helper already there):

```ts
test("a >2MB code file yields a LOW unscanned-content finding", async () => {
  const big = "x".repeat(3 * 1024 * 1024);
  const tgz = await makeTgz({ "package/package.json": '{"name":"a","version":"1.0.0"}', "package/bundle.js": big });
  const report = await auditTarball({ meta: metaFor("a"), tarball: tgz });
  const f = report.findings.find((x) => x.ruleId === "unscanned-content");
  assert.ok(f && f.severity === "low", "unscanned large code should be a low finding");
});

test("a native binary + install script escalates unscanned-content to MEDIUM", async () => {
  const tgz = await makeTgz({
    "package/package.json": '{"name":"b","version":"1.0.0","scripts":{"postinstall":"node x"}}',
    "package/addon.node": "\0\0binary",
  });
  const report = await auditTarball({ meta: metaFor("b"), tarball: tgz });
  const f = report.findings.find((x) => x.ruleId === "unscanned-content");
  assert.ok(f && f.severity === "medium", "native + install scripts should escalate to medium");
});

test("a benign package has no unscanned-content finding", async () => {
  const tgz = await makeTgz({ "package/package.json": '{"name":"c","version":"1.0.0"}', "package/index.js": "module.exports=1\n" });
  const report = await auditTarball({ meta: metaFor("c"), tarball: tgz });
  assert.ok(!report.findings.some((x) => x.ruleId === "unscanned-content"));
});
```

- [ ] **Step 2: Run — expect FAIL**

Run: `node --import tsx --test packages/core/test/audit.test.ts`
Expected: FAIL (no `unscanned-content` finding).

- [ ] **Step 3: Synthesize the finding.** In `packages/core/src/audit.ts`, in the synthesis block (right after the `if (extracted.truncated) { … resource-abuse … }` push), add:

```ts
  if (extracted.unscanned.length > 0) {
    const nativeCount = extracted.unscanned.filter((u) => u.kind === "native").length;
    const totalBytes = extracted.unscanned.reduce((s, u) => s + u.size, 0);
    const mb = (totalBytes / (1024 * 1024)).toFixed(1);
    const escalate = nativeCount > 0 && detectInstallScripts(extracted.files);
    audit.findings.push({
      ruleId: "unscanned-content", category: "metadata",
      severity: escalate ? "medium" : "low",
      message: escalate
        ? `${extracted.unscanned.length} executable-looking file(s) (${mb} MB) were not scanned, including ${nativeCount} native/binary, and the package runs install scripts`
        : `${extracted.unscanned.length} executable-looking file(s) (${mb} MB) were not scanned (${nativeCount} native, ${extracted.unscanned.length - nativeCount} large-code)`,
      onChangedFile: false, evidence: [],
    });
  }
```

(`detectInstallScripts` is a module-level function already defined in `audit.ts`; call it directly. If it is not in scope from `runAudit`, confirm its declaration and call it as-is — do not duplicate its logic.)

- [ ] **Step 4: Run — expect PASS**

Run: `node --import tsx --test packages/core/test/audit.test.ts && node --import tsx --test packages/core/test/extract.test.ts`
Expected: PASS both.

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/audit.ts packages/core/test/audit.test.ts
git commit -m "feat(core): runAudit surfaces unscanned executable-looking content as a finding (low; medium w/ native+install)"
```

---

### Task 4: Require an SLSA v1 predicate for provenance `verified` (#12)

**Files:**
- Modify: `packages/core/src/provenance.ts` (downgrade non-SLSA-only to `unknown`)
- Modify: `packages/core/src/rules/provenance.ts` (soften the `unknown` message)
- Test: `packages/core/test/provenance.test.ts` (add/adjust cases)

**Interfaces:**
- Consumes/Produces: `verifyProvenance(...)` returns `unknown` (not `verified`) when bundles verify + bind but none is SLSA v1; the distinct reason is `"attestation present but no recognized SLSA v1 provenance predicate"`.

- [ ] **Step 1: Write the failing test.** First read `packages/core/test/provenance.test.ts` to learn how it builds bundles / mocks the verifier. Add a case that constructs a bundle set which passes verification + subject binding but whose predicateType is NOT `https://slsa.dev/provenance/v1`, and assert:

```ts
// (shape: adapt to the file's existing bundle/verifier construction helpers)
const res = verifyProvenance({ /* claimed:true, trust, attestations with a non-SLSA predicate, integrity matching */ });
assert.equal(res.status, "unknown");
assert.equal(res.identity, null);
assert.match(res.reason ?? "", /no recognized SLSA v1/i);
```

If an existing test asserts a non-SLSA bundle yields `status: "verified"` (the old buggy behavior the review flagged), update it to the corrected `unknown` expectation. Keep any existing SLSA-v1 test asserting `verified` unchanged.

- [ ] **Step 2: Run — expect FAIL**

Run: `node --import tsx --test packages/core/test/provenance.test.ts`
Expected: FAIL (currently returns `verified`).

- [ ] **Step 3: Require the SLSA predicate.** In `packages/core/src/provenance.ts`, change the verify loop + return:

```ts
  try {
    const verifier = buildVerifier(input.trust);
    let identity: ProvenanceIdentity | null = null;
    let sawSlsa = false;
    for (const a of list) {
      const bundle = bundleFromJSON(a.bundle);
      const result = verifier.verify(toSignedEntity(bundle));
      const stmt = statementOf(bundle);
      const bindErr = checkSubjectBinding(stmt, input.integrity);
      if (bindErr) return { status: "invalid", identity: null, reason: bindErr, rootStale };
      if (stmt.predicateType === SLSA_V1) { identity = extractIdentity(result, stmt); sawSlsa = true; }
    }
    if (!sawSlsa) {
      return { status: "unknown", identity: null,
        reason: "attestation present but no recognized SLSA v1 provenance predicate", rootStale };
    }
    return { status: "verified", identity, reason: null, rootStale };
  } catch (e) {
    return { status: "invalid", identity: null, reason: (e as Error)?.message ?? "attestation verification failed", rootStale };
  }
```

- [ ] **Step 4: Soften the provenance rule's `unknown` message.** In `packages/core/src/rules/provenance.ts`, change the `provenance === "unknown"` line:

```ts
    else if (provenance === "unknown") add("low", "provenance attested but not established as verified SLSA v1 provenance (unrecognized predicate, bundle unavailable, or no trust material)");
```

- [ ] **Step 5: Run — expect PASS**

Run: `node --import tsx --test packages/core/test/provenance.test.ts packages/core/test/provenance-rule.test.ts`
Expected: PASS. `provenance-rule.test.ts` covers the rule; if it asserts the OLD `unknown` message text verbatim, update that assertion to match the softened message (or a looser `/not established as verified/i` match). Also run any requireProvenance/identity-gate test present (`node --import tsx --test packages/core/test/*provenance*.test.ts`) to confirm no regression.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/provenance.ts packages/core/src/rules/provenance.ts packages/core/test/provenance.test.ts
git commit -m "fix(core): require an SLSA v1 predicate for provenance 'verified' (non-SLSA ⇒ unknown) (#12)"
```

---

### Task 5: Docs, ADR-0041, and PR

**Files:**
- Create: `docs/adr/0041-review-hardening.md`
- Modify: `CLAUDE.md`, `ARCHITECTURE.md`

- [ ] **Step 1: Write ADR-0041** — `docs/adr/0041-review-hardening.md`, following the format of a recent ADR (read `docs/adr/0040-violation-sensing-vs-enforcement.md` for structure). Cover the two behavioral changes: (a) **#11** — a LOW `unscanned-content` finding (MEDIUM with native + install scripts) makes the >2 MB / non-text scan blind spot non-silent; extends the extract-coverage design; never hard-blocks. (b) **#12** — provenance `verified` now requires an SLSA v1 predicate; a valid-but-non-SLSA attestation maps to `unknown` (reusing the status, no new value); extends ADR-0022, does not supersede it; the `requireProvenance` gate and the `invalid`-on-error mapping are unchanged. Note #10 (SHA pinning) as CI hygiene included in the same PR.

- [ ] **Step 2: Update `CLAUDE.md`** — add a Phase 27 paragraph to the phase log covering all three (#10 SHA pinning, #11 `unscanned-content` synthesized finding, #12 SLSA-predicate requirement). Note `unscanned-content` is synthesized in `runAudit` (not a registered rule, so the rule count is unchanged).

- [ ] **Step 3: Update `ARCHITECTURE.md`** — in the extract/scan-coverage area, note the `unscanned-content` finding and the executable-looking classification; in the provenance section (ADR-0022 area), note the SLSA-predicate requirement for `verified`. Cite ADR-0041.

- [ ] **Step 4: Full build + test**

Run: `npm run build && npm test 2>&1 | grep -E "^ℹ (tests|pass|fail|skipped)"`
Expected: build clean; `fail 0`; count is prior total + the new tests; **confirm the malicious fixture still blocks** and benign fixtures score unchanged (they carry no large-code/native content and real SLSA provenance).

- [ ] **Step 5: Commit and open the PR**

```bash
git add docs/adr/0041-review-hardening.md CLAUDE.md ARCHITECTURE.md
git commit -m "docs: ADR-0041 + docs for review hardening (#10, #11, #12)"
git push -u origin review-hardening
gh pr create --base main --title "Review hardening: pin Action SHAs, surface unscanned content, require SLSA predicate (closes #10 #11 #12)" --body "$(cat <<'EOF'
Closes #10, #11, #12 (P2/P3 items from the external security review).

- **#10**: every third-party Action `uses:` pinned to a commit SHA (`# vX.Y.Z` comment); CONTRIBUTING notes the update path.
- **#11**: `extractTarball` tracks counted-but-unscanned executable-looking files (large code >2 MB + native/wasm binaries); `runAudit` surfaces a LOW `unscanned-content` finding, MEDIUM when a native binary co-occurs with install scripts. Never hard-blocks alone.
- **#12**: `verifyProvenance` now requires an SLSA v1 predicate for `verified`; a valid-but-non-SLSA attestation maps to `unknown` (legit npm packages keep `verified` — they carry an SLSA bundle). Gate + invalid-on-error unchanged.

ADR-0041 covers #11/#12. Suite green; malicious fixture still blocks.
https://claude.ai/code/session_01SyQAokqoA3eYGniZWdeggf
EOF
)"
```

---

## Notes for the executor

- Tasks 2→3 are ordered (Task 3's finding reads Task 2's `unscanned` field). Task 4 (#12) and Task 1 (#10) are independent of the #11 pair.
- Category weighting is by severity — `unscanned-content` needs no policy edit; LOW/MEDIUM contribute via `severityWeight` and never hard-block.
- Do NOT register `unscanned-content` in `rules/index.ts` — it is synthesized in `runAudit`, like `resource-abuse`/`integrity-mismatch`.
- If any existing provenance test encoded the old non-SLSA-→-`verified` behavior, that is the bug #12 fixes — update the expectation, don't preserve it.

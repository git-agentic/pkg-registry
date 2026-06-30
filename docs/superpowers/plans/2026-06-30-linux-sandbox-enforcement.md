# Linux Sandbox Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port Sentinel's macOS Seatbelt sandbox enforcement to Linux using bubblewrap (`bwrap`), behind a platform-selecting factory, so lifecycle scripts run under enforced least-privilege on Linux too.

**Architecture:** Decouple the `Sandbox` interface from SBPL — `run()` takes structured policy (`approved` capabilities + `homeDir`) and each backend compiles internally. `SeatbeltSandbox` keeps emitting SBPL; a new `BubblewrapSandbox` emits `bwrap` argv via a new pure `generateBwrapArgs`. `createSandbox()` selects the backend by platform and fails closed elsewhere. `SENSITIVE_PATHS` gains a `platforms` tag so each backend gets its OS-appropriate persistence paths from one shared source.

**Tech Stack:** Node 24 (also 22), TypeScript (NodeNext ESM, `.js` specifiers), npm workspaces, `node:test` + `tsx`, `bubblewrap` on Linux, `sandbox-exec` on macOS.

## Global Constraints

- **ESM only** (`"type": "module"`); internal imports use `.js` specifiers even from `.ts` sources (NodeNext). No top-level `require`.
- **Profile generators are pure & deterministic** — same inputs ⇒ identical output. Generators filter `SENSITIVE_PATHS` by a **fixed** platform argument (NOT `process.platform`), so `generateProfile` emits the darwin set even when its tests run on Linux CI.
- **Fail closed:** a sandbox that cannot enforce **throws / refuses** — it never runs a lifecycle script unsandboxed. Off-platform backends throw.
- **Tests assert on the protected-resource EFFECT** (planted secret never obtained, planted file unchanged, host unreachable), never on exit codes.
- **Effect-tests are platform-gated:** Linux effect-tests skip on darwin; macOS effect-tests skip on non-darwin. Pure generator/unit tests run everywhere.
- **Build:** `npm run build` is `tsc --build`. The working tree may be on a mount where `rm` of build artifacts fails with EPERM — use `npx tsc --build --force <pkg>` instead of deleting `dist/`.
- **Test baseline before this work:** `npm test` is 136/136 (135 pass, 1 darwin-only skip). Keep it honest; the final task records the new totals.
- Synthetic malware fixtures are scored-as-text and **never executed**; enforcement is tested with benign probe commands only.
- Probe environment for Linux work: a Colima VM is running (`colima ssh -- bash <script>`); `bwrap` needs `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` on Ubuntu 24.04.

---

### Task 1: Extract the shared path-coverage matcher

Move `pathCovers`/`segments` out of `profile.ts` into a shared module so both backends match capability coverage identically (invariant: an approval can't cancel a deny on one platform but not the other).

**Files:**
- Create: `packages/sandbox/src/path-cover.ts`
- Modify: `packages/sandbox/src/profile.ts` (remove the two local functions, import them)
- Test: `packages/sandbox/test/path-cover.test.ts`

**Interfaces:**
- Produces: `segments(p: string): string[]` and `pathCovers(approvedTarget: string, denyPath: string): boolean` — moved verbatim from `profile.ts`.

- [ ] **Step 1: Write the failing test**

```ts
// packages/sandbox/test/path-cover.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { pathCovers, segments } from "../src/path-cover.js";

describe("pathCovers", () => {
  test("segment-anchored, not substring: 'ssh' does NOT cover '.ssh'", () => {
    assert.equal(pathCovers("ssh", "~/.ssh"), false);
  });
  test("an exact segment covers its own deny path", () => {
    assert.equal(pathCovers(".ssh", "~/.ssh"), true);
  });
  test("the dynamic '*' target covers nothing", () => {
    assert.equal(pathCovers("*", "~/.npmrc"), false);
  });
  test("ancestor covers descendant and vice-versa (shared prefix to shorter)", () => {
    assert.equal(pathCovers("/etc/passwd", "/etc/passwd"), true);
    assert.equal(segments("~/.aws/credentials").join("/"), ".aws/credentials");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/sandbox/test/path-cover.test.ts`
Expected: FAIL — `Cannot find module '../src/path-cover.js'`.

- [ ] **Step 3: Create the shared module (move the functions verbatim)**

```ts
// packages/sandbox/src/path-cover.ts

/** Split a path into segments after stripping a leading `~/` or `/`. */
export function segments(p: string): string[] {
  return p.replace(/^~?\/?/, "").split("/").filter(Boolean);
}

/**
 * Path-segment-anchored coverage: true iff an approved filesystem target and a deny
 * path share a full segment prefix up to the shorter (one is an ancestor-or-equal of
 * the other). Deliberately NOT a substring match — `ssh` does not cover `.ssh`, and
 * the dynamic `*` capability target covers nothing.
 */
export function pathCovers(approvedTarget: string, denyPath: string): boolean {
  const a = segments(approvedTarget);
  const d = segments(denyPath);
  if (a.length === 0) return false;
  const n = Math.min(a.length, d.length);
  for (let i = 0; i < n; i++) if (a[i] !== d[i]) return false;
  return true;
}
```

- [ ] **Step 4: Update `profile.ts` to import instead of define**

In `packages/sandbox/src/profile.ts`: delete the local `segments` and `pathCovers` function definitions (lines ~15–42, keep the `NOTE — descendant-covers-ancestor` doc comment by moving it to `path-cover.ts` if desired), and add at the top after the existing import:

```ts
import { pathCovers } from "./path-cover.js";
```

(Leave `canonicalizeMacPath` in `profile.ts` — it is macOS-only.)

- [ ] **Step 5: Run tests to verify all pass**

Run: `npx tsx --test packages/sandbox/test/path-cover.test.ts packages/sandbox/test/profile.test.ts`
Expected: PASS (profile.test.ts still green — pure refactor).

- [ ] **Step 6: Commit**

```bash
git add packages/sandbox/src/path-cover.ts packages/sandbox/src/profile.ts packages/sandbox/test/path-cover.test.ts
git commit -m "refactor(sandbox): extract pathCovers/segments to shared path-cover util"
```

---

### Task 2: Platform-tagged SENSITIVE_PATHS + `sensitivePathsFor` (core)

Add a `platforms` tag so each backend draws its OS-appropriate persistence paths from the one shared source. Add Linux persistence entries. Pin `generateProfile` to the darwin set.

**Files:**
- Modify: `packages/core/src/sensitive-paths.ts`
- Modify: `packages/core/src/index.ts` (export `sensitivePathsFor`)
- Modify: `packages/sandbox/src/profile.ts` (iterate `sensitivePathsFor("darwin")`)
- Test: `packages/core/test/sensitive-paths.test.ts` (create); update `packages/sandbox/test/profile.test.ts`

**Interfaces:**
- Consumes: `pathCovers` (Task 1).
- Produces:
  - `SensitivePath` gains `platforms?: ("darwin" | "linux")[]` (absent ⇒ applies to both).
  - `sensitivePathsFor(platform: "darwin" | "linux"): SensitivePath[]` — entries whose `platforms` is absent or includes `platform`.

- [ ] **Step 1: Write the failing test (core)**

```ts
// packages/core/test/sensitive-paths.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { sensitivePathsFor } from "../src/index.js";

const labels = (platform: "darwin" | "linux") => sensitivePathsFor(platform).map((s) => s.label);

describe("sensitivePathsFor", () => {
  test("shared credential paths appear on both platforms", () => {
    for (const p of ["darwin", "linux"] as const) {
      assert.ok(labels(p).includes("SSH private keys"));
      assert.ok(labels(p).includes("npm auth token (~/.npmrc)"));
    }
  });
  test("macOS-only persistence paths appear only on darwin", () => {
    assert.ok(labels("darwin").includes("user LaunchAgents"));
    assert.ok(!labels("linux").includes("user LaunchAgents"));
  });
  test("Linux-only persistence paths appear only on linux", () => {
    assert.ok(labels("linux").includes("systemd user units (~/.config/systemd/user)"));
    assert.ok(labels("linux").includes("crontab spool (Linux)"));
    assert.ok(!labels("darwin").includes("systemd user units (~/.config/systemd/user)"));
  });
  test("shell rc files are shared (both platforms)", () => {
    for (const p of ["darwin", "linux"] as const) assert.ok(labels(p).includes("shell rc (~/.bashrc)"));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/core/test/sensitive-paths.test.ts`
Expected: FAIL — `sensitivePathsFor` is not exported.

- [ ] **Step 3: Edit `sensitive-paths.ts`**

Add `platforms?` to the interface (after `detectRe?`):

```ts
  /** Code-detection regex for `secret-exfil`; omit for deny-only paths. */
  detectRe?: RegExp;
  /** Which OS this entry applies to; absent ⇒ both. Backends filter via sensitivePathsFor(). */
  platforms?: ("darwin" | "linux")[];
}
```

Tag the macOS-only persistence entries with `platforms: ["darwin"]` (the four LaunchAgents/LaunchDaemons entries and the `~/Library` ones plus the macOS crontab spool). Replace the persistence block (the entries from `shell rc (~/.zshrc)` through `crontab spool`) with:

```ts
  // Persistence / tamper targets — write-only (no secret to read; the threat is dropping
  // an autostart payload or appending to a startup file):
  { label: "shell rc (~/.zshrc)", denyPaths: ["~/.zshrc"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.zshenv)", denyPaths: ["~/.zshenv"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.bashrc)", denyPaths: ["~/.bashrc"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.bash_profile)", denyPaths: ["~/.bash_profile"], denyKind: "literal", modes: ["write"] },
  { label: "shell rc (~/.profile)", denyPaths: ["~/.profile"], denyKind: "literal", modes: ["write"] },
  { label: "XDG autostart", denyPaths: ["~/.config/autostart"], denyKind: "subpath", modes: ["write"], platforms: ["linux"] },
  { label: "systemd user units (~/.config/systemd/user)", denyPaths: ["~/.config/systemd/user"], denyKind: "subpath", modes: ["write"], platforms: ["linux"] },
  { label: "systemd user units (~/.local/share/systemd/user)", denyPaths: ["~/.local/share/systemd/user"], denyKind: "subpath", modes: ["write"], platforms: ["linux"] },
  { label: "crontab spool (Linux)", denyPaths: ["/var/spool/cron/crontabs"], denyKind: "subpath", modes: ["write"], platforms: ["linux"] },
  { label: "user LaunchAgents", denyPaths: ["~/Library/LaunchAgents"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "user LaunchDaemons", denyPaths: ["~/Library/LaunchDaemons"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "system LaunchAgents", denyPaths: ["/Library/LaunchAgents"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "system LaunchDaemons", denyPaths: ["/Library/LaunchDaemons"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
  { label: "crontab spool (macOS)", denyPaths: ["/var/at/tabs"], denyKind: "subpath", modes: ["write"], platforms: ["darwin"] },
];
```

Then add the helper at the end of the file:

```ts
/** SENSITIVE_PATHS applicable to `platform` (entries with no `platforms` tag apply to both). */
export function sensitivePathsFor(platform: "darwin" | "linux"): SensitivePath[] {
  return SENSITIVE_PATHS.filter((sp) => !sp.platforms || sp.platforms.includes(platform));
}
```

- [ ] **Step 4: Export from core**

In `packages/core/src/index.ts`, add `sensitivePathsFor` to the existing `sensitive-paths.js` export (alongside `SENSITIVE_PATHS` / `SensitivePath`). Example:

```ts
export { SENSITIVE_PATHS, sensitivePathsFor, type SensitivePath } from "./sensitive-paths.js";
```

- [ ] **Step 5: Pin `generateProfile` to the darwin set**

In `packages/sandbox/src/profile.ts`: change the import to pull `sensitivePathsFor` and replace `for (const sp of SENSITIVE_PATHS)` with `for (const sp of sensitivePathsFor("darwin"))`.

```ts
import { sensitivePathsFor, type Capability } from "@sentinel/core";
```

- [ ] **Step 6: Guard the darwin pin in `profile.test.ts`**

Append to the `generateProfile` describe block in `packages/sandbox/test/profile.test.ts`:

```ts
  test("emits darwin persistence paths but NOT linux-only ones (pinned to darwin set)", () => {
    const p = generateProfile([], { homeDir: HOME });
    assert.match(p, /LaunchAgents/);                         // darwin entry present
    assert.doesNotMatch(p, /systemd\/user/);                 // linux-only entry absent
    assert.doesNotMatch(p, /spool\/cron/);                   // linux-only entry absent
  });
```

- [ ] **Step 7: Build core, run tests**

Run: `npx tsc --build --force packages/core && npx tsx --test packages/core/test/sensitive-paths.test.ts packages/sandbox/test/profile.test.ts`
Expected: PASS. (`profile.test.ts` still asserts LaunchAgents/`/var/at/tabs` — those stay in the darwin set.)

- [ ] **Step 8: Commit**

```bash
git add packages/core/src/sensitive-paths.ts packages/core/src/index.ts packages/core/test/sensitive-paths.test.ts packages/sandbox/src/profile.ts packages/sandbox/test/profile.test.ts
git commit -m "feat(core): platforms tag + sensitivePathsFor; add Linux persistence paths; pin generateProfile to darwin set"
```

---

### Task 3: `generateBwrapArgs` — the pure Linux profile generator

Emit `bwrap` argv replicating Seatbelt's allow-default + targeted-deny, using the probe-confirmed mapping: `subpath` → `--tmpfs`, `literal` → `--ro-bind /dev/null`, `--unshare-net` unless network approved.

**Files:**
- Create: `packages/sandbox/src/bwrap.ts`
- Test: `packages/sandbox/test/bwrap.test.ts`

**Interfaces:**
- Consumes: `pathCovers` (Task 1), `sensitivePathsFor` (Task 2), `Capability` from `@sentinel/core`.
- Produces: `generateBwrapArgs(approved: Capability[], opts: { homeDir: string }): string[]` — argv to pass after `bwrap` (before `/bin/sh -c <cmd>`).

- [ ] **Step 1: Write the failing test**

```ts
// packages/sandbox/test/bwrap.test.ts
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { generateBwrapArgs } from "../src/bwrap.js";
import type { Capability } from "@sentinel/core";

const fs = (target: string): Capability => ({ kind: "filesystem", target, evidence: [] });
const net = (target: string): Capability => ({ kind: "network", target, evidence: [] });
const HOME = "/home/test";
const argv = (a: Capability[]) => generateBwrapArgs(a, { homeDir: HOME }).join(" ");

describe("generateBwrapArgs", () => {
  test("binds root read-write and sets up /dev and /proc", () => {
    assert.match(argv([]), /--bind \/ \/ --dev \/dev --proc \/proc/);
  });
  test("masks credential DIRECTORIES with --tmpfs (subpath)", () => {
    assert.match(argv([]), /--tmpfs \/home\/test\/\.ssh/);
    assert.match(argv([]), /--tmpfs \/home\/test\/\.aws/);
  });
  test("masks credential FILES with --ro-bind /dev/null (literal)", () => {
    assert.match(argv([]), /--ro-bind \/dev\/null \/home\/test\/\.npmrc/);
    assert.match(argv([]), /--ro-bind \/dev\/null \/etc\/passwd/);  // no firmlink canonicalization on Linux
  });
  test("includes Linux persistence paths, not macOS ones", () => {
    const a = argv([]);
    assert.match(a, /--tmpfs \/home\/test\/\.config\/systemd\/user/);
    assert.match(a, /--tmpfs \/var\/spool\/cron\/crontabs/);
    assert.doesNotMatch(a, /LaunchAgents/);
    assert.doesNotMatch(a, /var\/at\/tabs/);
  });
  test("denies all network with --unshare-net when no network approval", () => {
    assert.match(argv([]), /--unshare-net/);
  });
  test("an approved network capability omits --unshare-net", () => {
    assert.doesNotMatch(argv([net("api.example.com")]), /--unshare-net/);
  });
  test("a filesystem approval omits its deny (both read and write side)", () => {
    const a = argv([fs(".npmrc")]);
    assert.doesNotMatch(a, /\/home\/test\/\.npmrc/);   // the ~/.npmrc mask is gone
    assert.match(a, /\.ssh/);                          // unrelated denies remain
  });
  test("filesystem coverage is path-segment-anchored, not substring", () => {
    assert.match(argv([fs("ssh")]), /--tmpfs \/home\/test\/\.ssh/);  // 'ssh' must NOT cancel '.ssh'
    assert.doesNotMatch(argv([fs(".ssh")]), /--tmpfs \/home\/test\/\.ssh/);  // exact segment cancels
  });
  test("deterministic for the same inputs", () => {
    assert.deepEqual(generateBwrapArgs([net("x")], { homeDir: HOME }), generateBwrapArgs([net("x")], { homeDir: HOME }));
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: FAIL — `Cannot find module '../src/bwrap.js'`.

- [ ] **Step 3: Implement `generateBwrapArgs`**

```ts
// packages/sandbox/src/bwrap.ts
import { sensitivePathsFor, type Capability } from "@sentinel/core";
import { pathCovers } from "./path-cover.js";

/**
 * Generate `bwrap` argv from a package's APPROVED capabilities, replicating the macOS
 * allow-default + targeted-deny model on Linux (probe-verified on Ubuntu 24.04):
 *   - allow-default read+write     → `--bind / /` (+ `--dev /dev --proc /proc`)
 *   - credential DIR  (subpath)    → `--tmpfs <path>`        (content masked, writes discarded)
 *   - credential FILE (literal)    → `--ro-bind /dev/null <path>` (read empty, write EPERM)
 *   - network deny                 → `--unshare-net`
 * Both mask mechanics are robust to a nonexistent target and cover read AND write, so the
 * read/write `modes` distinction is not needed here. An approved `filesystem`/`network`
 * capability omits the corresponding deny (same `pathCovers` semantics as the SBPL side).
 * Pure: same inputs ⇒ same argv. No firmlink canonicalization (Linux has no firmlinks).
 */
export function generateBwrapArgs(approved: Capability[], opts: { homeDir: string }): string[] {
  const expand = (p: string) => (p.startsWith("~") ? opts.homeDir + p.slice(1) : p);
  const approvedFs = approved.filter((c) => c.kind === "filesystem").map((c) => c.target);
  const hasNetwork = approved.some((c) => c.kind === "network");

  const args = ["--bind", "/", "/", "--dev", "/dev", "--proc", "/proc"];
  for (const sp of sensitivePathsFor("linux")) {
    for (const dp of sp.denyPaths) {
      if (approvedFs.some((t) => pathCovers(t, dp))) continue;
      const target = expand(dp);
      if (sp.denyKind === "subpath") args.push("--tmpfs", target);
      else args.push("--ro-bind", "/dev/null", target);
    }
  }
  if (!hasNetwork) args.push("--unshare-net");
  return args;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `npx tsx --test packages/sandbox/test/bwrap.test.ts`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/sandbox/src/bwrap.ts packages/sandbox/test/bwrap.test.ts
git commit -m "feat(sandbox): generateBwrapArgs — pure Linux profile generator (tmpfs/ro-bind/unshare-net)"
```

---

### Task 4: Refactor the `Sandbox` interface to structured policy; migrate Seatbelt + runner

Change `Sandbox.run` to take `{ cwd, approved, homeDir, env }` (no pre-compiled `profile` string). `SeatbeltSandbox` compiles SBPL internally; `runLifecycleScripts` forwards structured policy. Migrate the macOS tests to the new interface using fake homes + real generators (this also unifies the test shape with the upcoming Linux effect-tests).

**Files:**
- Modify: `packages/sandbox/src/types.ts`
- Modify: `packages/sandbox/src/seatbelt.ts`
- Modify: `packages/sandbox/src/runner.ts`
- Modify: `packages/sandbox/test/seatbelt.test.ts`
- Modify: `packages/sandbox/test/runner.test.ts`

**Interfaces:**
- Consumes: `generateProfile` (existing), `scrubEnv` (existing), `Capability`.
- Produces:
  - `Sandbox.run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv }): SandboxResult`
  - `runLifecycleScripts(opts: { packageDir: string; sandbox: Sandbox; approved?: Capability[]; homeDir: string }): { results: ScriptResult[]; failed: boolean }`

- [ ] **Step 1: Update the `Sandbox` interface**

```ts
// packages/sandbox/src/types.ts
import type { Capability } from "@sentinel/core";

export interface SandboxResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface Sandbox {
  /** Run `cmd` (via `sh -c`) under a sandbox compiled from the APPROVED capabilities, in `cwd`. */
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv }): SandboxResult;
}
```

- [ ] **Step 2: Update `SeatbeltSandbox` to compile internally**

In `packages/sandbox/src/seatbelt.ts`, add `import { generateProfile } from "./profile.js";` and `import type { Capability } from "@sentinel/core";`, and change the signature + first line of `run`:

```ts
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv }): SandboxResult {
    if (process.platform !== "darwin") {
      throw new Error(`sandbox enforcement unavailable on ${process.platform} (macOS Seatbelt required)`);
    }
    const profile = generateProfile(opts.approved, { homeDir: opts.homeDir });
    const dir = mkdtempSync(join(tmpdir(), "sentinel-sb-"));
    const profileFile = join(dir, "profile.sb");
    writeFileSync(profileFile, profile);
    // ... rest unchanged (spawnSync sandbox-exec -f profileFile ...) ...
```

- [ ] **Step 3: Update `runLifecycleScripts`**

In `packages/sandbox/src/runner.ts`, change the options object and the `sandbox.run` call:

```ts
export function runLifecycleScripts(opts: {
  packageDir: string;
  sandbox: Sandbox;
  approved?: Capability[];
  homeDir: string;
}): { results: ScriptResult[]; failed: boolean } {
  let scripts: Record<string, string> = {};
  try {
    scripts = JSON.parse(readFileSync(join(opts.packageDir, "package.json"), "utf8"))?.scripts ?? {};
  } catch {
    scripts = {};
  }
  const approved = opts.approved ?? [];
  const env = scrubEnv(process.env, approved);
  const results: ScriptResult[] = [];
  for (const hook of LIFECYCLE) {
    const command = scripts[hook];
    if (!command) continue;
    const r = opts.sandbox.run(command, { cwd: opts.packageDir, approved, homeDir: opts.homeDir, env });
    results.push({ hook, command, exitCode: r.exitCode });
  }
  return { results, failed: results.some((r) => r.exitCode !== 0) };
}
```

- [ ] **Step 4: Migrate `runner.test.ts` to the new interface**

In `packages/sandbox/test/runner.test.ts`, update `fakeSandbox` and the two `runLifecycleScripts` calls:

```ts
function fakeSandbox(captured: NodeJS.ProcessEnv[]): Sandbox {
  return { run(_cmd, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv }): SandboxResult {
    captured.push(opts.env ?? {});
    return { exitCode: 0, stdout: "", stderr: "" };
  } };
}
```

Replace both calls' `profile: "(version 1)\n(allow default)\n"` argument with `homeDir: "/home/test"`:

```ts
      runLifecycleScripts({ packageDir: dir, sandbox: fakeSandbox(captured), approved, homeDir: "/home/test" });
      // ...
      runLifecycleScripts({ packageDir: dir, sandbox: fakeSandbox(captured2), approved: [], homeDir: "/home/test" });
```

- [ ] **Step 5: Migrate `seatbelt.test.ts` to the new interface (fake home + real generator)**

Rewrite the enforcement cases to pass `{ cwd, approved, homeDir, env }`. Full replacement for `packages/sandbox/test/seatbelt.test.ts`:

```ts
import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, realpathSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { SeatbeltSandbox } from "../src/seatbelt.js";
import { runLifecycleScripts } from "../src/runner.js";
import { scrubEnv } from "../src/env.js";
import type { Capability } from "@sentinel/core";

const darwin = process.platform === "darwin";

describe("SeatbeltSandbox (fail-closed)", () => {
  test("non-darwin throws (we never run unsandboxed)", { skip: darwin ? "darwin: covered by enforcement tests" : false }, () => {
    assert.throws(() => new SeatbeltSandbox().run("echo hi", { cwd: tmpdir(), approved: [], homeDir: "/tmp" }), /unavailable/i);
  });
});

describe("SeatbeltSandbox enforcement", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("a denied credential read leaves the secret unobtained (assert on EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-read-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-XYZ");
    const out = join(home, "out.txt");
    new SeatbeltSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    const got = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!got.includes("TOPSECRET-XYZ"), "the secret bytes must NOT have been obtained");
  });

  test("a denied network connection never lands (loopback listener)", async () => {
    const got: boolean[] = [];
    const server = net.createServer((s) => { got.push(true); s.destroy(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-net-")));
    new SeatbeltSandbox().run(`nc -z -G 2 127.0.0.1 ${port} || true`, { cwd: home, approved: [], homeDir: home });
    await new Promise((r) => setTimeout(r, 200));
    server.close();
    assert.equal(got.length, 0, "the sandboxed connection must not have reached the listener");
  });

  test("an unapproved credential env-var never reaches the script (assert on EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-env-")));
    const out = join(home, "leak.txt");
    const cmd = `node -e "require('fs').writeFileSync('${out}', String(process.env.SECRET_API_KEY||''))"`;
    const env = scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, []);
    new SeatbeltSandbox().run(cmd, { cwd: home, approved: [], homeDir: home, env });
    assert.ok(!(existsSync(out) ? readFileSync(out, "utf8") : "").includes("TOPSECRET-ENV"), "the credential env-var must not have reached the script");

    const approved: Capability[] = [{ kind: "env", target: "SECRET_API_KEY", evidence: [] }];
    const env2 = scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, approved);
    new SeatbeltSandbox().run(cmd, { cwd: home, approved, homeDir: home, env: env2 });
    assert.ok(readFileSync(out, "utf8").includes("TOPSECRET-ENV"), "an approved env var is passed through");
  });

  test("an unapproved write to a sensitive path is denied (planted file unchanged)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-write-")));
    const rc = join(home, ".zshrc");        // write-only persistence entry
    const allowed = join(home, "allowed.txt");
    writeFileSync(rc, "ORIGINAL");
    new SeatbeltSandbox().run(`echo OK > "${allowed}"; echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(allowed, "utf8").trim(), "OK", "script must have executed (positive control)");
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the denied write must have been blocked");
  });

  test("a filesystem approval relaxes the write deny at the kernel level (criterion 3)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "sb-fsapprove-")));
    const rc = join(home, ".zshrc");
    writeFileSync(rc, "ORIGINAL");
    new SeatbeltSandbox().run(`echo INJECTED >> "${rc}" 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "unapproved write to ~/.zshrc must be blocked");
    const approved: Capability[] = [{ kind: "filesystem", target: ".zshrc", evidence: [] }];
    new SeatbeltSandbox().run(`echo INJECTED >> "${rc}"`, { cwd: home, approved, homeDir: home });
    assert.ok(readFileSync(rc, "utf8").includes("INJECTED"), "an approved filesystem write must succeed");
  });
});

describe("runLifecycleScripts", { skip: darwin ? false : "requires macOS sandbox-exec" }, () => {
  test("runs present hooks under the sandbox and a benign script succeeds", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "sb-run-")));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo built > built.txt" } }));
    const r = runLifecycleScripts({ packageDir: dir, sandbox: new SeatbeltSandbox(), homeDir: process.env.HOME ?? "/tmp" });
    assert.equal(r.failed, false);
    assert.equal(r.results.length, 1);
    assert.equal(r.results[0]?.hook, "postinstall");
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8").trim(), "built");
  });
});
```

- [ ] **Step 6: Build sandbox + run the suite (on darwin) / verify it compiles (anywhere)**

Run: `npx tsc --build --force packages/sandbox && npx tsx --test packages/sandbox/test/runner.test.ts packages/sandbox/test/seatbelt.test.ts`
Expected: on darwin — PASS (enforcement tests run); on Linux — runner test passes, seatbelt enforcement describe **skipped**, `non-darwin throws` runs & passes. No type errors either way.

- [ ] **Step 7: Commit**

```bash
git add packages/sandbox/src/types.ts packages/sandbox/src/seatbelt.ts packages/sandbox/src/runner.ts packages/sandbox/test/seatbelt.test.ts packages/sandbox/test/runner.test.ts
git commit -m "refactor(sandbox): Sandbox.run takes structured policy; backends compile internally"
```

---

### Task 5: `BubblewrapSandbox` + `createSandbox` factory + CLI wiring

Add the Linux backend (fail-closed on missing `bwrap` / refused namespace), the platform-selecting factory, the package exports, and rewire the CLI to use the factory instead of a hardcoded darwin gate.

**Files:**
- Create: `packages/sandbox/src/bubblewrap.ts`
- Create: `packages/sandbox/src/factory.ts`
- Modify: `packages/sandbox/src/index.ts`
- Modify: `packages/cli/src/index.ts:200-232`
- Test: `packages/sandbox/test/factory.test.ts`

**Interfaces:**
- Consumes: `generateBwrapArgs` (Task 3), `Sandbox` (Task 4), `SeatbeltSandbox`.
- Produces:
  - `class BubblewrapSandbox implements Sandbox`
  - `createSandbox(): Sandbox` — `darwin`→`SeatbeltSandbox`, `linux`→`BubblewrapSandbox`, else throws.

- [ ] **Step 1: Write the failing test (factory + fail-closed)**

```ts
// packages/sandbox/test/factory.test.ts
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { describe, test } from "node:test";
import { createSandbox } from "../src/factory.js";
import { BubblewrapSandbox } from "../src/bubblewrap.js";
import { SeatbeltSandbox } from "../src/seatbelt.js";

describe("createSandbox", () => {
  test("selects the backend for the host platform (fails closed elsewhere)", () => {
    if (process.platform === "darwin") assert.ok(createSandbox() instanceof SeatbeltSandbox);
    else if (process.platform === "linux") assert.ok(createSandbox() instanceof BubblewrapSandbox);
    else assert.throws(() => createSandbox(), /unavailable/i);
  });
});

describe("BubblewrapSandbox (fail-closed)", () => {
  test("non-linux throws (we never run unsandboxed)", { skip: process.platform === "linux" ? "linux: covered by enforcement tests" : false }, () => {
    assert.throws(() => new BubblewrapSandbox().run("echo hi", { cwd: tmpdir(), approved: [], homeDir: "/tmp" }), /unavailable/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx --test packages/sandbox/test/factory.test.ts`
Expected: FAIL — `Cannot find module '../src/factory.js'` / `'../src/bubblewrap.js'`.

- [ ] **Step 3: Implement `BubblewrapSandbox`**

```ts
// packages/sandbox/src/bubblewrap.ts
import { spawnSync } from "node:child_process";
import { generateBwrapArgs } from "./bwrap.js";
import type { Sandbox, SandboxResult } from "./types.js";
import type { Capability } from "@sentinel/core";

/** bwrap's own errors when the kernel refuses unprivileged user namespaces (Ubuntu 24.04 AppArmor, etc.). */
const NS_FAILURE = /Creating new namespace failed|No permissions to create new namespace|setting up uid map/i;

/** Enforces a generated bwrap profile via `bwrap`. Fails closed on non-Linux, missing bwrap, or refused namespace. */
export class BubblewrapSandbox implements Sandbox {
  run(cmd: string, opts: { cwd: string; approved: Capability[]; homeDir: string; env?: NodeJS.ProcessEnv }): SandboxResult {
    if (process.platform !== "linux") {
      throw new Error(`bubblewrap enforcement unavailable on ${process.platform} (Linux required)`);
    }
    const args = [...generateBwrapArgs(opts.approved, { homeDir: opts.homeDir }), "/bin/sh", "-c", cmd];
    const res = spawnSync("bwrap", args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.error && (res.error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error("bubblewrap enforcement unavailable: `bwrap` not found on PATH (install the bubblewrap package)");
    }
    if (res.error) {
      throw new Error(`bubblewrap enforcement failed: ${res.error.message}`);
    }
    if (NS_FAILURE.test(res.stderr ?? "")) {
      throw new Error(`bubblewrap enforcement unavailable: kernel refused user-namespace creation — ${res.stderr?.trim()}`);
    }
    return {
      exitCode: res.status ?? (res.signal ? 1 : 0),
      stdout: res.stdout ?? "",
      stderr: res.stderr ?? "",
    };
  }
}
```

- [ ] **Step 4: Implement `createSandbox`**

```ts
// packages/sandbox/src/factory.ts
import type { Sandbox } from "./types.js";
import { SeatbeltSandbox } from "./seatbelt.js";
import { BubblewrapSandbox } from "./bubblewrap.js";

/** Select the enforcement backend for the host platform. Fails closed on unsupported platforms. */
export function createSandbox(): Sandbox {
  switch (process.platform) {
    case "darwin": return new SeatbeltSandbox();
    case "linux": return new BubblewrapSandbox();
    default: throw new Error(`sandbox enforcement unavailable on ${process.platform} (macOS or Linux required)`);
  }
}
```

- [ ] **Step 5: Export the new surface**

Replace `packages/sandbox/src/index.ts` with:

```ts
export { generateProfile } from "./profile.js";
export { generateBwrapArgs } from "./bwrap.js";
export type { Sandbox, SandboxResult } from "./types.js";
export { SeatbeltSandbox } from "./seatbelt.js";
export { BubblewrapSandbox } from "./bubblewrap.js";
export { createSandbox } from "./factory.js";
export { runLifecycleScripts, type ScriptResult } from "./runner.js";
export { scrubEnv, ENV_ALLOWLIST } from "./env.js";
```

- [ ] **Step 6: Rewire the CLI to the factory**

In `packages/cli/src/index.ts`: update the import on line 14 to `import { createSandbox, runLifecycleScripts } from "@sentinel/sandbox";` (drop `generateProfile`, `SeatbeltSandbox`). Update the `run-scripts` description and `.action` body (lines ~201–232):

```ts
  .description("Run a package's lifecycle scripts under a sandbox derived from its approved capabilities (macOS Seatbelt / Linux bubblewrap).")
```

Remove the `if (process.platform !== "darwin") { … process.exit(2); }` block (lines 205–208). Replace the profile/sandbox construction (old lines 231–232) with:

```ts
    let sandbox;
    try {
      sandbox = createSandbox();
    } catch (e) {
      console.error(`\x1b[31msentinel: ${(e as Error).message}\x1b[0m`);
      process.exit(2);
    }
    const { results, failed } = runLifecycleScripts({ packageDir: dir, sandbox, approved, homeDir: homedir() });
```

(Leave the `detected` / `parseApprovals` / network + env notes and the results/`failed` reporting unchanged.)

- [ ] **Step 7: Build everything; run sandbox + CLI tests**

Run: `npm run build && npx tsx --test packages/sandbox/test/factory.test.ts`
Expected: PASS. On darwin: factory returns `SeatbeltSandbox`, `BubblewrapSandbox non-linux throws` runs & passes. On Linux: factory returns `BubblewrapSandbox`, that throw-test skipped.

- [ ] **Step 8: Commit**

```bash
git add packages/sandbox/src/bubblewrap.ts packages/sandbox/src/factory.ts packages/sandbox/src/index.ts packages/sandbox/test/factory.test.ts packages/cli/src/index.ts
git commit -m "feat(sandbox): BubblewrapSandbox + createSandbox factory; CLI run-scripts uses the factory (macOS/Linux)"
```

---

### Task 6: Linux enforcement effect-tests (gated linux, skipped on darwin)

Prove the protected-resource effects on a real Linux kernel, mirroring the Seatbelt enforcement tests. These run in CI (Linux) and skip on the dev's Mac.

**Files:**
- Create: `packages/sandbox/test/bubblewrap.test.ts`

**Interfaces:**
- Consumes: `BubblewrapSandbox` (Task 5), `runLifecycleScripts` (Task 4), `scrubEnv`.

- [ ] **Step 1: Write the effect-tests**

```ts
// packages/sandbox/test/bubblewrap.test.ts
import assert from "node:assert/strict";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import { BubblewrapSandbox } from "../src/bubblewrap.js";
import { runLifecycleScripts } from "../src/runner.js";
import { scrubEnv } from "../src/env.js";
import type { Capability } from "@sentinel/core";

const bwrapWorks = (() => {
  if (process.platform !== "linux") return false;
  const r = spawnSync("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "true"], { encoding: "utf8" });
  return !r.error && r.status === 0;
})();
const skip = process.platform !== "linux"
  ? "requires Linux"
  : (bwrapWorks ? false : "bwrap cannot create namespaces here (see ci.yml: apparmor_restrict_unprivileged_userns=0)");

describe("BubblewrapSandbox enforcement", { skip }, () => {
  test("a denied credential read leaves the secret unobtained (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-read-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "TOPSECRET-XYZ");
    const out = join(home, "out.txt");
    new BubblewrapSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    const got = existsSync(out) ? readFileSync(out, "utf8") : "";
    assert.ok(!got.includes("TOPSECRET-XYZ"), "the secret bytes must NOT have been obtained");
    assert.equal(readFileSync(join(home, ".ssh", "id_rsa"), "utf8"), "TOPSECRET-XYZ", "real secret untouched");
  });

  test("a denied network connection never lands (loopback listener)", async () => {
    const got: boolean[] = [];
    const server = net.createServer((s) => { got.push(true); s.destroy(); });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as net.AddressInfo).port;
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-net-")));
    // Connect via node, not a /dev/tcp bashism — BubblewrapSandbox runs `/bin/sh -c`, which is
    // dash on Ubuntu (no /dev/tcp). Under --unshare-net the sandbox has its own netns, so this
    // 127.0.0.1 cannot reach the host listener; the assertion is on the listener side (EFFECT).
    const connect = `node -e "const s=require('net').connect(${port},'127.0.0.1');s.on('connect',()=>s.end());s.on('error',()=>{});setTimeout(()=>process.exit(0),400)"`;
    new BubblewrapSandbox().run(connect, { cwd: home, approved: [], homeDir: home });
    await new Promise((r) => setTimeout(r, 200));
    server.close();
    assert.equal(got.length, 0, "the sandboxed connection must not have reached the listener");
  });

  test("an unapproved write to a persistence path is denied (planted file unchanged)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-write-")));
    const rc = join(home, ".bashrc");
    const allowed = join(home, "allowed.txt");
    writeFileSync(rc, "ORIGINAL");
    new BubblewrapSandbox().run(`echo OK > "${allowed}"; echo PWNED >> "${rc}" 2>/dev/null || true`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(allowed, "utf8").trim(), "OK", "script must have executed (positive control)");
    assert.equal(readFileSync(rc, "utf8"), "ORIGINAL", "the denied write must have been blocked");
  });

  test("an unapproved credential env-var never reaches the script; approval passes it through (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-env-")));
    const out = join(home, "leak.txt");
    const cmd = `node -e "require('fs').writeFileSync('${out}', String(process.env.SECRET_API_KEY||''))"`;
    new BubblewrapSandbox().run(cmd, { cwd: home, approved: [], homeDir: home, env: scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, []) });
    assert.ok(!(existsSync(out) ? readFileSync(out, "utf8") : "").includes("TOPSECRET-ENV"), "the credential env-var must not have reached the script");
    const approved: Capability[] = [{ kind: "env", target: "SECRET_API_KEY", evidence: [] }];
    new BubblewrapSandbox().run(cmd, { cwd: home, approved, homeDir: home, env: scrubEnv({ ...process.env, SECRET_API_KEY: "TOPSECRET-ENV" }, approved) });
    assert.ok(readFileSync(out, "utf8").includes("TOPSECRET-ENV"), "an approved env var is passed through");
  });

  test("a filesystem approval relaxes the credential read deny (EFFECT)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-fsapprove-")));
    mkdirSync(join(home, ".ssh"));
    writeFileSync(join(home, ".ssh", "id_rsa"), "APPROVED-SECRET");
    const out = join(home, "out.txt");
    const approved: Capability[] = [{ kind: "filesystem", target: ".ssh", evidence: [] }];
    new BubblewrapSandbox().run(`cat ${join(home, ".ssh", "id_rsa")} > ${out} 2>/dev/null || true`, { cwd: home, approved, homeDir: home });
    assert.ok(readFileSync(out, "utf8").includes("APPROVED-SECRET"), "an approved filesystem read must succeed");
  });

  test("a non-denied path stays readable and writable inside the sandbox (positive control)", () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "bw-allow-")));
    writeFileSync(join(home, "data.txt"), "HELLO");
    const out = join(home, "copy.txt");
    new BubblewrapSandbox().run(`cat ${join(home, "data.txt")} > ${out}`, { cwd: home, approved: [], homeDir: home });
    assert.equal(readFileSync(out, "utf8").trim(), "HELLO", "non-denied read/write must work");
  });

  test("runLifecycleScripts runs a benign postinstall under bwrap", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "bw-run-")));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0", scripts: { postinstall: "echo built > built.txt" } }));
    const r = runLifecycleScripts({ packageDir: dir, sandbox: new BubblewrapSandbox(), homeDir: process.env.HOME ?? "/root" });
    assert.equal(r.failed, false);
    assert.equal(readFileSync(join(dir, "built.txt"), "utf8").trim(), "built");
  });
});
```

- [ ] **Step 2: Run on darwin to confirm it SKIPS cleanly**

Run: `npx tsx --test packages/sandbox/test/bubblewrap.test.ts`
Expected (on darwin): the describe is skipped (`requires Linux`); no failures.

- [ ] **Step 3: Run on Linux (Colima VM) to confirm the effects hold**

```bash
# from the repo root on the host:
cp -r . ~/.sentinel-src 2>/dev/null || true   # only if the tree isn't already under the mounted home
colima ssh -- bash -lc '
  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
  command -v bwrap >/dev/null || sudo apt-get update -qq && sudo apt-get install -y -qq bubblewrap nodejs npm
  cd ~/.sentinel-src && npm ci && npm run build && npx tsx --test packages/sandbox/test/bubblewrap.test.ts'
```
Expected: the `BubblewrapSandbox enforcement` describe RUNS and all cases PASS. (If the repo tree is not under the Colima-mounted home, copy it there first; the exact path may differ — confirm the mount with `colima ssh -- ls ~`.)

- [ ] **Step 4: Commit**

```bash
git add packages/sandbox/test/bubblewrap.test.ts
git commit -m "test(sandbox): Linux bwrap enforcement effect-tests (gated linux + bwrap-available)"
```

---

### Task 7: CI mitigation + docs (ADR-0018, ARCHITECTURE, CLAUDE.md)

Make CI actually exercise the Linux effect-tests, and record the design decision and honest test counts.

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `docs/adr/0018-cross-platform-sandbox-backends.md`
- Modify: `docs/adr/README.md` (index the new ADR)
- Modify: `ARCHITECTURE.md` (§3.6)
- Modify: `CLAUDE.md` (Phase summary intro + `npm test` count line)

- [ ] **Step 1: Add the bwrap install + userns mitigation to CI**

In `.github/workflows/ci.yml`, insert two steps after `- uses: actions/setup-node@v4` (with its `with:` block) and before `- run: npm ci`:

```yaml
      - run: sudo apt-get update && sudo apt-get install -y bubblewrap
      - run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # Ubuntu 24.04 restricts unprivileged user namespaces; bwrap needs this (probe-verified)
```

- [ ] **Step 2: Write ADR-0018**

```markdown
# ADR-0018: Cross-platform sandbox backends (bubblewrap on Linux)

**Status:** Accepted (Phase 5)
**Date:** 2026-06-30

## Context
Phases 3–4 enforce an approved capability manifest at install time on macOS via Seatbelt.
Off-darwin, `SeatbeltSandbox` throws (fail-closed) — so Linux, where most CI and agent
installs run, got *refusal*, not *enforcement*. We need the same least-privilege on Linux.

## Decision
Add a Linux enforcement backend using **bubblewrap (`bwrap`)** and select the backend by
platform via `createSandbox()` (darwin→Seatbelt, linux→Bubblewrap, else throw).

- **Why bubblewrap, not Landlock/seccomp.** Sentinel's model is *allow-default + deny
  specific paths*. Landlock is allow-list-only — it cannot deny a subpath of a granted
  hierarchy, so "allow `~` except `~/.ssh`" is inexpressible — and needs a native helper
  (no Node binding). bubblewrap replicates the existing model exactly: `--bind / /`
  (allow-default read+write), then mask each sensitive path. Probe-verified on Ubuntu 24.04.
- **Deny mapping (probe-confirmed).** `denyKind: "subpath"` → `--tmpfs <path>` (content
  masked, writes land on a throwaway tmpfs so persistence payloads do not survive);
  `denyKind: "literal"` → `--ro-bind /dev/null <path>` (reads return empty, writes EPERM).
  Both are robust to a nonexistent target and cover read **and** write, so the bwrap side
  does not need the read/write `modes` split the SBPL side uses. `--unshare-net` denies all
  network unless a `network` capability is approved (all-or-nothing, same as Seatbelt; per-
  host fidelity stays on the proxy). No firmlink canonicalization (Linux has no firmlinks).
- **Interface.** `Sandbox.run` now takes structured policy (`approved` + `homeDir`); each
  backend compiles its own profile (SBPL or bwrap argv) internally. The runner/CLI no longer
  know SBPL exists. Capability-coverage matching (`pathCovers`) is shared, so an approval
  cannot cancel a deny on one platform but not the other.
- **Platform-specific persistence paths.** `SENSITIVE_PATHS` entries carry an optional
  `platforms` tag; `sensitivePathsFor(platform)` filters. Credential + shell-rc paths are
  shared; LaunchAgents/LaunchDaemons/`/var/at/tabs` are darwin; systemd-user units, XDG
  autostart, and `/var/spool/cron/crontabs` are linux. Each generator is pinned to a fixed
  platform (not `process.platform`) so it is deterministic regardless of the test host.

## Fail-closed
`BubblewrapSandbox` throws (never runs the script unsandboxed) when not on Linux, when
`bwrap` is absent, or when the kernel refuses user-namespace creation. On **Ubuntu 24.04**
unprivileged user namespaces are AppArmor-restricted by default
(`kernel.apparmor_restrict_unprivileged_userns=1`); CI sets it to `0` so the Linux
effect-tests can enforce. This is documented and load-bearing — verified empirically before
implementation.

## Consequences
- Linux installs get the same credential-read, network-egress, and persistence-write denial
  macOS already had. Effect-tests run in CI (Linux) and skip on the dev's Mac; the macOS
  effect-tests run on the Mac and skip in CI — each platform is verified somewhere.
- bwrap is an external dependency (must be installed) and needs unprivileged user namespaces
  enabled. Both are handled in CI; operators on locked-down hosts get a loud fail-closed error.

## Rejected
- **Landlock + seccomp** — wrong model fit (allow-list-only), native-helper burden, kernel-
  version churn (network rules need ABI v4 / kernel 6.7).
- **Stacking seccomp on bwrap "for depth"** — YAGNI; no in-scope threat needs syscall filtering.
- **Reusing the `profile: string` slot for bwrap argv** — leaky abstraction; backends own
  their own compilation.

Supersedes nothing; extends ADR-0016 (which deferred non-macOS enforcement) and ADR-0017
(which `SENSITIVE_PATHS.modes` come from).
```

- [ ] **Step 3: Index the ADR**

Add a line for ADR-0018 to `docs/adr/README.md` following the existing format/ordering.

- [ ] **Step 4: Update ARCHITECTURE.md §3.6**

In `ARCHITECTURE.md` §3.6, update the opening sentence so enforcement is no longer macOS-only, and add a paragraph after the env/write-confinement paragraphs:

```markdown
**Cross-platform backends (Phase 5, ADR-0018).** Enforcement runs on macOS *and* Linux behind
`createSandbox()`: darwin → `SeatbeltSandbox` (SBPL), linux → `BubblewrapSandbox` (`bwrap`
argv), any other platform → fail-closed throw. `Sandbox.run` takes the *approved capabilities*
+ `homeDir`; each backend compiles its own profile, so the runner/CLI are backend-agnostic.
The Linux deny model mirrors Seatbelt via bind/overlay: credential **dirs** → `--tmpfs`,
credential/persistence **files** → `--ro-bind /dev/null`, all-or-nothing network → `--unshare-net`;
each relaxed by an approved `filesystem`/`network` capability through the shared `pathCovers`
matcher. Persistence paths are platform-tagged in `SENSITIVE_PATHS` (`sensitivePathsFor`).
On Ubuntu 24.04, unprivileged user namespaces are AppArmor-restricted by default; CI relaxes
`kernel.apparmor_restrict_unprivileged_userns`, and the backend fails closed if the kernel
still refuses.
```

Also adjust the §3.6 first line: change "turns an *approved* capability set into *enforced*
runtime least-privilege on macOS" to "… on macOS and Linux".

- [ ] **Step 5: Update CLAUDE.md**

In `CLAUDE.md`: update the Phase summary block to add a Phase 5 line (Linux bubblewrap
enforcement behind `createSandbox`), and change the §"What this is" sandbox sentence from
"macOS Seatbelt runner" framing to "macOS Seatbelt / Linux bubblewrap runner, selected by
`createSandbox()`."

- [ ] **Step 6: Record the honest test count**

Run the full suite on the dev host and read the actual totals:

Run: `npm run build && npm test 2>&1 | tail -20`
Expected (on darwin): all pass except the Linux effect-tests, which report as **skipped**
(`requires Linux`), plus the pre-existing `non-darwin throws`-style skips. Note the exact
`# pass` / `# skip` / total numbers tests print.

Update the `CLAUDE.md` `npm test` line to state the real totals and the platform split, e.g.:
"`npm test` — N/N (P pass, S skipped on this host). Skips are platform-gated enforcement:
the macOS effect-tests skip in Linux CI; the Linux bwrap effect-tests skip on macOS. Each
platform's enforcement is verified on that platform." Use the actual N/P/S you observed.

- [ ] **Step 7: Verify build + full suite green, then commit**

Run: `npm run build && npm test`
Expected: green (Linux effect-tests skipped on darwin; everything else passes).

```bash
git add .github/workflows/ci.yml docs/adr/0018-cross-platform-sandbox-backends.md docs/adr/README.md ARCHITECTURE.md CLAUDE.md
git commit -m "docs+ci(phase5): ADR-0018 cross-platform backends; CI bwrap+userns mitigation; ARCHITECTURE/CLAUDE updates"
```

---

## Self-Review

**Spec coverage:**
- §1 success criteria 1–4 (read/write/network deny + approval relax) → Task 6 effect-tests (+ Task 3 generator tests for the argv shape).
- §1 criterion 5 (fail closed) → Task 5 (`BubblewrapSandbox` throws on non-linux / missing bwrap / refused namespace) + Task 5 factory test; CI mitigation Task 7.
- §1 criterion 6 (no drift) → Task 1 shared `pathCovers`; Task 2 single `SENSITIVE_PATHS` source.
- §1 criterion 7 (determinism) → Task 3 determinism test; Task 2 pins generators to a fixed platform.
- §3 interface refactor → Task 4. §4 invocation mapping → Task 3 (+ probe-confirmed). §5 fail-closed → Task 5. §6 CI/tests → Tasks 6–7. §8 scope → no seccomp/Landlock, no `install --enforce`, Windows throws (Task 5 factory default). §9 DoD → Task 7.

**Placeholder scan:** No "TBD"/"add error handling"/"similar to". The only emergent value — the exact `npm test` totals — is gathered by a concrete command in Task 7 Step 6 and written from the observed output (test counts genuinely cannot be known before the suite exists).

**Type consistency:** `Sandbox.run(cmd, { cwd, approved, homeDir, env? })` is defined in Task 4 and used identically in Tasks 4–6. `generateBwrapArgs(approved, { homeDir })`, `sensitivePathsFor(platform)`, `createSandbox()`, `runLifecycleScripts({ packageDir, sandbox, approved?, homeDir })`, `pathCovers`/`segments` — all names match across the tasks that define and consume them.

// Release-hygiene gate: every publishable workspace tarball must contain ONLY
// runtime files. This test runs `npm pack --dry-run --json` per workspace and
// fails if a forbidden file (tests, fixtures, keys, env files, source maps,
// compiled native binaries, internal docs, ...) would enter a published
// tarball, or if a required runtime asset is missing.
//
// Requires `npm run build` to have produced dist/ (CI builds before testing).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

const WORKSPACES = ["core", "proxy", "sandbox", "cli", "mcp", "action", "steward"] as const;

/** Path patterns that must never appear in a published tarball. */
const FORBIDDEN: { name: string; re: RegExp }[] = [
  { name: "test files", re: /(^|\/)test(s)?\/|\.test\./ },
  { name: "fixtures", re: /(^|\/)fixtures\// },
  { name: "TypeScript sources", re: /^src\// },
  { name: "source maps", re: /\.map$/ },
  { name: "tsbuildinfo", re: /\.tsbuildinfo$/ },
  { name: "private keys / PEM material", re: /\.(pem|key)$|\.key\.|private.*key/i },
  { name: "env files", re: /(^|\/)\.env(\.|$)/ },
  { name: "databases", re: /\.(db|sqlite3?)$/ },
  { name: "git metadata", re: /(^|\/)\.git(\/|$|ignore$|attributes$)/ },
  { name: "node_modules", re: /(^|\/)node_modules\// },
  { name: "coverage output", re: /(^|\/)coverage\// },
  { name: "OS junk", re: /\.DS_Store$/ },
  { name: "compiled landlock helper (must never ship prebuilt)", re: /^dist\/landlock-exec$/ },
  { name: "tsconfig", re: /tsconfig.*\.json$/ },
  { name: "agent/internal docs", re: /(^|\/)(CLAUDE|AGENTS)\.md$|\.superpowers\// },
  { name: "local stores", re: /\.sentinel-store\.json$|sentinel-history/ },
];

/** Per-workspace runtime assets that MUST be present. */
const REQUIRED: Record<(typeof WORKSPACES)[number], string[]> = {
  core: ["dist/index.js", "dist/index.d.ts", "trust/trusted-root.json", "trust/npm-attestation-keys.json", "LICENSE", "README.md", "package.json"],
  proxy: ["dist/index.js", "dist/registry-cli.js", "dist/server.js", "public/index.html", "LICENSE", "README.md", "package.json"],
  sandbox: ["dist/index.js", "native/landlock-exec.c", "scripts/build-native.mjs", "LICENSE", "README.md", "package.json"],
  cli: ["dist/index.js", "dist/script-shell.js", "LICENSE", "README.md", "package.json"],
  mcp: ["dist/index.js", "LICENSE", "README.md", "package.json"],
  action: ["dist/index.js", "LICENSE", "README.md", "package.json"],
  steward: ["dist/index.js", "LICENSE", "README.md", "package.json"],
};

function packList(pkgDir: string): string[] {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: pkgDir,
    encoding: "utf8",
    // npm pack --dry-run writes the JSON report to stdout and progress to stderr
    stdio: ["ignore", "pipe", "ignore"],
  });
  const parsed = JSON.parse(out) as [{ files: { path: string }[] }];
  return parsed[0].files.map((f) => f.path);
}

for (const ws of WORKSPACES) {
  test(`@sentinel/${ws} tarball contains only runtime files`, () => {
    const pkgDir = join(repoRoot, "packages", ws);
    assert.ok(
      existsSync(join(pkgDir, "dist", "index.js")),
      `packages/${ws}/dist missing — run \`npm run build\` before the package-contents test`,
    );
    const files = packList(pkgDir);

    const violations: string[] = [];
    for (const f of files) {
      for (const { name, re } of FORBIDDEN) {
        if (re.test(f)) violations.push(`${f} (${name})`);
      }
    }
    assert.deepEqual(violations, [], `forbidden files in @sentinel/${ws} tarball:\n  ${violations.join("\n  ")}`);

    for (const req of REQUIRED[ws]) {
      assert.ok(files.includes(req), `@sentinel/${ws} tarball is missing required runtime file: ${req}`);
    }
  });
}

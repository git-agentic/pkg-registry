import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { describe, test } from "node:test";
import { parse } from "yaml";
import { LocalFixtureUpstream } from "@git-agentic/sentinel-proxy";
import type { TreeAuditResult } from "@git-agentic/sentinel-core";
import { renderPrComment, REPORT_MARKER } from "../src/report.js";
import { runCi } from "../src/run.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const FIXTURES = join(REPO, "fixtures");

describe("PR comment marker is only trusted on the bot's own comment", () => {
  const doc = parse(readFileSync(join(REPO, "action.yml"), "utf8")) as { runs: { steps: { uses?: string; with?: { script?: string } }[] } };
  const script = doc.runs.steps.find((s) => s.uses?.startsWith("actions/github-script"))!.with!.script!;
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as new (...args: string[]) => (...args: unknown[]) => Promise<void>;

  async function runScript(comments: { id: number; body: string; user: { login: string; type: string } }[]) {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-comment-"));
    writeFileSync(join(dir, "sentinel-comment.md"), `${REPORT_MARKER}\nreport`);
    const calls: { op: "update" | "create"; id?: number }[] = [];
    // listComments alone returns only the first page (30 comments); paginate walks them all.
    const firstPage = comments.slice(0, 30);
    const listComments = async () => ({ data: firstPage });
    const github = { paginate: async (fn: unknown) => { assert.equal(fn, listComments); return comments; }, rest: { issues: {
      listComments,
      updateComment: async (a: { comment_id: number }) => { calls.push({ op: "update", id: a.comment_id }); },
      createComment: async () => { calls.push({ op: "create" }); },
    } } };
    const context = { repo: { owner: "o", repo: "r" }, issue: { number: 1 } };
    await new AsyncFunction("require", "github", "context", "process", script)(
      createRequire(import.meta.url), github, context, { env: { RUNNER_TEMP: dir } });
    return calls;
  }

  test("a comment carrying the marker from another user is never edited", async () => {
    const calls = await runScript([{ id: 7, body: `${REPORT_MARKER} fake`, user: { login: "mallory", type: "User" } }]);
    assert.deepEqual(calls, [{ op: "create" }]);
  });

  test("a user spoofing the bot login without the Bot type is ignored", async () => {
    const calls = await runScript([{ id: 8, body: REPORT_MARKER, user: { login: "github-actions[bot]", type: "User" } }]);
    assert.deepEqual(calls, [{ op: "create" }]);
  });

  test("the bot's marker comment beyond the first page of 30 is still found", async () => {
    const filler = Array.from({ length: 30 }, (_, i) => ({ id: 100 + i, body: "chatter", user: { login: "dev", type: "User" } }));
    const calls = await runScript([...filler, { id: 9, body: REPORT_MARKER, user: { login: "github-actions[bot]", type: "Bot" } }]);
    assert.deepEqual(calls, [{ op: "update", id: 9 }]);
  });

  test("the github-actions bot's own marker comment is still updated in place", async () => {
    const calls = await runScript([
      { id: 7, body: `${REPORT_MARKER} fake`, user: { login: "mallory", type: "User" } },
      { id: 9, body: REPORT_MARKER, user: { login: "github-actions[bot]", type: "Bot" } },
    ]);
    assert.deepEqual(calls, [{ op: "update", id: 9 }]);
  });
});

describe("workflow-command escaping", () => {
  test("annotation text cannot start a second workflow command", async () => {
    if (!existsSync(join(FIXTURES, "registry.json")) || !existsSync(join(FIXTURES, ".tarballs"))) {
      execFileSync("npx", ["tsx", join(REPO, "scripts", "make-fixtures.ts")], { cwd: REPO, stdio: "ignore" });
    }
    const dir = mkdtempSync(join(tmpdir(), "sentinel-wfcmd-"));
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify({ name: "demo", lockfileVersion: 3, packages: {
      "": { name: "demo" }, "node_modules/color-stream": { version: "1.4.1" } } }));
    const realFetch = globalThis.fetch;
    // Inject attacker-controlled text where a package-supplied finding would land.
    globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
      const res = await realFetch(...args);
      const body = await res.json() as TreeAuditResult;
      body.packages[0]!.topFinding = "x 100%\n::set-output name=pwn::1\r::add-mask::y";
      return new Response(JSON.stringify(body), { status: res.status, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    const lines: string[] = [];
    const realLog = console.log;
    console.log = (...a: unknown[]) => { lines.push(a.join(" ")); };
    try {
      await runCi({ upstream: new LocalFixtureUpstream(FIXTURES), cwd: dir, sbomPath: join(dir, "sbom.json"),
        failOn: "block", omitDev: false, now: "2026-07-08T00:00:00Z", env: { GITHUB_STEP_SUMMARY: join(dir, "summary.md") } });
    } finally { console.log = realLog; globalThis.fetch = realFetch; }
    const annotation = lines.find((l) => l.startsWith("::error::"));
    assert.ok(annotation, "blocked package is annotated");
    assert.equal(/[\r\n]/.test(annotation!), false, "no raw line break inside one annotation");
    assert.match(annotation!, /100%25%0A::set-output name=pwn::1%0D::add-mask::y/);
    for (const line of lines.join("\n").split(/\r?\n|\r/)) {
      assert.equal(/^::(?!error::|warning::)/.test(line), false, `unexpected workflow command on stdout: ${line}`);
    }
  });
});

describe("Markdown in the PR comment", () => {
  const hostile = "`x` <img src=x onerror=1> [click](https://evil.example) ![i](https://evil.example/p.png) @octocat \\| end";
  const result: TreeAuditResult = {
    aggregate: { verdict: "block", gated: true, counts: { allow: 0, warn: 0, block: 1, error: 0 },
      provenance: { verified: 0, invalid: 0, absent: 1, unknown: 0 }, integrityMismatch: 0 },
    packages: [{ name: "@evil/<b>pkg", version: "1.0.0", status: "block", score: 1, topFinding: hostile, topFindingRuleId: null,
      error: null, provenance: "absent", integrityMismatch: false }],
  };
  const row = renderPrComment(result, { now: "t" }).split("\n").find((l) => l.startsWith("| @") || l.startsWith("| \\@") || l.includes("evil"))!;

  test("backticks, angle brackets and link syntax are neutralized", () => {
    assert.equal(/(^|[^\\])[`<\[\]]/.test(row.replace(/\\\\/g, "")), false, `unescaped markdown metacharacter in: ${row}`);
  });

  test("@mentions are broken so they do not notify", () => {
    assert.equal(/@(?!​)/.test(row), false, `bare @ in: ${row}`);
    assert.ok(row.includes("@​octocat"));
  });

  test("pipes and newlines still cannot break the table", () => {
    assert.equal(row.split(/(?<!\\)\|/).length, 7, `table cells intact: ${row}`);
    const multiline = renderPrComment({ ...result, packages: [{ ...result.packages[0]!, topFinding: "a\nb" }] }, { now: "t" });
    assert.match(multiline, /a b/);
  });
});

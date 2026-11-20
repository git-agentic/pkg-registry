import type { AuditInput, ContentMismatchEntry, Evidence, Finding, Rule } from "../types.js";
import { codeFiles, headsWithTail, mkFinding, truncate } from "./util.js";
import { analyzeLoaderChain } from "../detect/loader-chain.js";

/**
 * Extensions acorn (a JavaScript parser) is expected to parse. A parse failure on
 * one of these is anomalous (minified/obfuscated JS) and warrants the regex
 * fallback. A parse failure on `.ts`/`.mts`/`.cts`/`.tsx`/`.jsx`/`.d.ts` is
 * EXPECTED — acorn does not parse TypeScript or JSX — so a regex co-occurrence
 * there is noise, not signal, and must NOT emit a finding. (Type-declaration
 * `.d.ts` files never execute at all.) Without this gate, every TypeScript file in
 * the ecosystem — e.g. `@types/node`'s hundreds of `.d.ts` — trips the fallback on
 * `readFile`/`write`/decode tokens in type signatures and stacks to a false block.
 */
const JS_PARSEABLE = /\.(c?js|mjs)$/i;

const GUNZIP_LIKE = /\b(gunzip|inflate|brotliDecompress|unzip)\w*\s*\(/;
const BUFFER_FROM = /Buffer\.from\(/g;
/** `require(<non-literal>)`, a template literal with `${`, or a literal `*.node` addon: loads a computed path, the launch form for a just-written native addon. */
/** A write whose target ends in `.node`, and a relative extension-less literal require (Node appends `.node`). */
const WRITES_NODE = /\b(?:writeFileSync|writeFile|createWriteStream|copyFileSync|copyFile)\s*\([^;\n]{0,200}\.node['"`]/;
const REQUIRE_EXTLESS = /\brequire\s*\(\s*(['"])\.\.?\/[^'".\n]*\1/;
const REQUIRE_OF_PATH = /\brequire\s*\(\s*(?:[^'"`\s)]|`[^`]*\$\{|(['"`])[^'"`\n]*\.node\1)/;
// Node accepts any case and `base64url` as an encoding name.
const BASE64 = /['"]base64(?:url)?['"]/gi;

/**
 * Under an overflow the file may use renamed destructured imports (`{readFileSync:r}=require("fs")`),
 * so a primitive counts when its name merely appears; the pad that defeated the parser must not also
 * hide a chain that is critical on its own.
 */
const LOOSE: Record<"read" | "decode" | "write" | "launch", RegExp> = {
  read: /\b(?:readFileSync|readFile|createReadStream)\b/,
  decode: /\b(?:gunzip|inflate|brotliDecompress|unzip)\w*/,
  write: /\b(?:writeFileSync|writeFile|createWriteStream)\b/,
  launch: /\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync)\b|process\.dlopen/,
};

/** Regex signals for the parse-failure fallback. Detect independently; NEVER claim dataflow. */
const FALLBACK: Record<"read" | "decode" | "write" | "launch", (src: string) => boolean> = {
  read: (src) => /\b(readFileSync|readFile|createReadStream)\s*\(/.test(src),
  // `Buffer.from(` + a base64 marker before the next `)`: linear, not `[^)]*` rescanned from every head.
  decode: (src) => GUNZIP_LIKE.test(src) || !headsWithTail(src, BUFFER_FROM, "\\)", BASE64).next().done,
  write: (src) => /\b(writeFileSync|writeFile|createWriteStream)\s*\(/.test(src),
  launch: (src) => /\b(spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\(|process\.dlopen\s*\(/.test(src),
};

const MAX_EXPORTS_DEPTH = 32;

/** Resolve entry-reachable file paths from package.json (main/bin/exports strings). No full Node resolution. */
function entryPaths(pkgJson: any): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => { if (typeof v === "string") out.add(norm(v)); };
  add(pkgJson?.main);
  if (typeof pkgJson?.bin === "string") add(pkgJson.bin);
  else if (pkgJson?.bin && typeof pkgJson.bin === "object") for (const v of Object.values(pkgJson.bin)) add(v);
  const exp = pkgJson?.exports;
  // Depth-bounded: a hostile 20k-deep `exports` must not overflow the stack and take the rule down.
  const collect = (e: any, depth: number) => {
    if (typeof e === "string") add(e);
    else if (depth < MAX_EXPORTS_DEPTH && e && typeof e === "object") for (const v of Object.values(e)) collect(v, depth + 1);
  };
  if (exp !== undefined) collect(exp, 0);
  if (out.size === 0) out.add("index.js"); // node default
  return out;
}
function norm(p: string): string { return p.replace(/^\.\//, "").replace(/^\//, ""); }

export const nativePayloadLoaderRule: Rule = {
  id: "native-payload-loader",
  category: "install-script",
  run(input: AuditInput): Finding[] {
    let pkgJson: any = {};
    const pj = input.files.find((f) => f.path === "package/package.json");
    if (pj) { try { pkgJson = JSON.parse(pj.content); } catch { pkgJson = {}; } }
    const entries = entryPaths(pkgJson);
    const mismatchByFile = new Map<string, ContentMismatchEntry[]>();
    for (const m of input.extractionObservations?.contentMismatch ?? []) {
      (mismatchByFile.get(m.path) ?? mismatchByFile.set(m.path, []).get(m.path)!).push(m);
    }

    const findings: Finding[] = [];
    for (const file of codeFiles(input)) {
      const rel = file.path.replace(/^package\//, "");
      const reachable = [...entries].some((e) => rel === e || rel.endsWith(`/${e}`) || e.endsWith(`/${rel}`));
      const a = analyzeLoaderChain(file.content, { moduleLoadReachable: reachable });

      if (a.parseFailed) {
        // Only fall back for genuinely-JS files: on TS/JSX/.d.ts a parse failure is
        // expected (acorn is JS-only), so a regex guess is noise, not signal.
        if (!JS_PARSEABLE.test(rel)) continue;
        // Regex fallback — independent signal only, capped below critical. Exception: an
        // overflow means hostile nesting defeated the parser, so a full read+decode+write+launch
        // chain is not downgraded (a pad of `x.b.b…` must not turn block into warn).
        const hits = (Object.keys(FALLBACK) as (keyof typeof FALLBACK)[]).filter((k) => FALLBACK[k](file.content) || (a.walkOverflow === true && LOOSE[k].test(file.content)));
        // The AST rule counts `require(<written path>)` as a launch; on an overflowed file the
        // fallback must too, or that launch form downgrades the chain to high.
        if (a.walkOverflow && !hits.includes("launch")
          && (REQUIRE_OF_PATH.test(file.content) || (WRITES_NODE.test(file.content) && REQUIRE_EXTLESS.test(file.content)))) hits.push("launch");
        if (hits.length >= 2) {
          findings.push(mkFinding({
            ruleId: this.id, category: this.category,
            severity: a.walkOverflow && hits.length === 4 ? "critical" : "high",
            message: `Possible payload loader (unparsed source, regex signal only): ${hits.join(" + ")} in \`${rel}\` — dataflow not verified.`,
            evidence: [{ file: file.path, snippet: truncate(file.content.trim().split("\n")[0] ?? "", 120) }],
            files: input.files,
          }));
        }
        continue;
      }

      const stages = new Set(a.primitives.map((p) => p.stage));
      const allFour = ["read", "decode", "write", "launch"].every((s) => stages.has(s as any));
      const evidence: Evidence[] = a.primitives.slice(0, 6).map((p) => ({ file: file.path, line: p.line, snippet: p.snippet }));
      const boosterList = Object.entries(a.boosters).filter(([, v]) => v).map(([k]) => k);
      // Spec6: the content-mismatch booster only fires when THIS loader's own read
      // target resolves to a file that has a content-mismatch observation — not when
      // ANY mismatch exists anywhere in the package (was: mismatchByFile.size > 0).
      const readTargets = a.primitives.filter((p) => p.stage === "read" && p.readTarget).map((p) => p.readTarget!);
      const mism = readTargets.some((rt) => {
        const base = rt.split("/").pop();
        for (const mismatchPath of mismatchByFile.keys()) {
          if (mismatchPath === rt || mismatchPath.endsWith(`/${rt}`) || (base && mismatchPath.endsWith(`/${base}`))) return true;
        }
        return false;
      });

      if (a.correlated) {
        findings.push(mkFinding({
          ruleId: this.id, category: this.category, severity: "critical",
          message: `Native-payload loader chain in \`${rel}\`: packaged read → decode → write → launch of the written file are dataflow-linked${boosterList.length ? ` (${boosterList.join(", ")}${mism ? ", content-mismatch" : ""})` : ""}.`,
          evidence, files: input.files,
        }));
      } else if (allFour) {
        findings.push(mkFinding({
          ruleId: this.id, category: this.category, severity: "high",
          message: `\`${rel}\` contains read+decode+write+launch primitives but no verified dataflow link — possible loader.`,
          evidence, files: input.files,
        }));
      } else if (stages.size >= 2 && (stages.has("write") || stages.has("decode"))) {
        // Require an actual materialization signal (a decode or a write). A bare
        // read+launch pair (e.g. read a secret, then exec curl to exfiltrate it) is
        // the generic shape already covered by secret-exfil/network-egress — not a
        // partial payload-loader pattern — so it must not fire here (avoids double
        // -counting unrelated malicious behavior as a loader finding).
        findings.push(mkFinding({
          ruleId: this.id, category: this.category, severity: "medium",
          message: `\`${rel}\` combines ${[...stages].join(" + ")} primitives — partial materialization pattern.`,
          evidence, files: input.files,
        }));
      }
    }
    return findings;
  },
};

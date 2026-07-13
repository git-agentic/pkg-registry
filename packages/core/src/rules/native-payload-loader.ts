import type { AuditInput, ContentMismatchEntry, Evidence, Finding, Rule } from "../types.js";
import { codeFiles, mkFinding, truncate } from "./util.js";
import { analyzeLoaderChain } from "../detect/loader-chain.js";

/** Regex signals for the parse-failure fallback. Detect independently; NEVER claim dataflow. */
const FALLBACK = {
  read: /\b(readFileSync|readFile|createReadStream)\s*\(/,
  decode: /\b(gunzip|inflate|brotliDecompress|unzip)\w*\s*\(|Buffer\.from\([^)]*['"]base64['"]/,
  write: /\b(writeFileSync|writeFile|createWriteStream)\s*\(/,
  launch: /\b(spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\(|process\.dlopen\s*\(/,
};

/** Resolve entry-reachable file paths from package.json (main/bin/exports strings). No full Node resolution. */
function entryPaths(pkgJson: any): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => { if (typeof v === "string") out.add(norm(v)); };
  add(pkgJson?.main);
  if (typeof pkgJson?.bin === "string") add(pkgJson.bin);
  else if (pkgJson?.bin && typeof pkgJson.bin === "object") for (const v of Object.values(pkgJson.bin)) add(v);
  const exp = pkgJson?.exports;
  const collect = (e: any) => {
    if (typeof e === "string") add(e);
    else if (e && typeof e === "object") for (const v of Object.values(e)) collect(v);
  };
  if (exp !== undefined) collect(exp);
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
        // Regex fallback — independent signal only, capped below critical.
        const hits = (Object.keys(FALLBACK) as (keyof typeof FALLBACK)[]).filter((k) => FALLBACK[k].test(file.content));
        if (hits.length >= 2) {
          findings.push(mkFinding({
            ruleId: this.id, category: this.category, severity: "high",
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

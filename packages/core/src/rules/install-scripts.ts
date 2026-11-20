import type { AuditInput, Finding, PackageFile, Rule } from "../types.js";
import { mkFinding, scanLines, truncate } from "./util.js";

const LIFECYCLE = ["preinstall", "install", "postinstall"] as const;

const DANGER_IN_SCRIPT = [
  { re: /\b(curl|wget)\b/i, why: "downloads from the network" },
  { re: /child_process|execSync|exec\(|spawn\(/i, why: "spawns a child process" },
  { re: /\beval\(|new Function\(/i, why: "evaluates dynamic code" },
  { re: /node\s+-e|-e\s+["']/i, why: "runs an inline node script" },
  { re: /process\.env/i, why: "reads environment variables" },
  { re: /base64|atob\(|from\(['"][A-Za-z0-9+/=]{40,}/i, why: "decodes an encoded blob" },
];

/**
 * Highest-signal rule: lifecycle scripts gate *execution* at install time.
 * Presence alone is informational; a script that also shells out, evaluates
 * code, or reads env/secrets escalates sharply.
 */
export const installScriptsRule: Rule = {
  id: "install-scripts",
  category: "install-script",
  run(input: AuditInput): Finding[] {
    const pkgJson = input.files.find((f) => f.path === "package/package.json");
    if (!pkgJson) return [];

    let scripts: Record<string, string> = {};
    try {
      scripts = (JSON.parse(pkgJson.content)?.scripts ?? {}) as Record<string, string>;
    } catch {
      return [];
    }

    const findings: Finding[] = [];
    const referencedFiles = makeResolver(input.files);

    for (const hook of LIFECYCLE) {
      const cmd = scripts[hook];
      if (typeof cmd !== "string" || !cmd) continue; // npm ignores non-string hooks; one must not throw the rule away

      // What does the lifecycle command itself do?
      const inlineDangers = DANGER_IN_SCRIPT.filter((d) => d.re.test(cmd));

      // If it runs a local script file, inspect that file's contents too.
      const referenced = referencedFiles(cmd);
      const fileDangers = referenced.flatMap((f) =>
        DANGER_IN_SCRIPT.flatMap((d) =>
          scanLines(f, d.re, 2).map((ev) => ({ why: d.why, ev })),
        ),
      );

      if (inlineDangers.length === 0 && fileDangers.length === 0) {
        findings.push(
          mkFinding({
            ruleId: this.id,
            category: this.category,
            severity: "low",
            message: `Declares a \`${hook}\` lifecycle script that runs on install: \`${truncate(cmd, 80)}\``,
            evidence: [{ file: "package/package.json", snippet: `"${hook}": "${truncate(cmd, 120)}"` }],
            files: input.files,
          }),
        );
        continue;
      }

      const reasons = [
        ...new Set([...inlineDangers.map((d) => d.why), ...fileDangers.map((d) => d.why)]),
      ];
      const evidence = [
        { file: "package/package.json", snippet: `"${hook}": "${truncate(cmd, 120)}"` },
        ...fileDangers.map((d) => d.ev),
      ];
      findings.push(
        mkFinding({
          ruleId: this.id,
          category: this.category,
          severity: "critical",
          message: `\`${hook}\` lifecycle script executes dangerous behaviour on install: ${reasons.join(", ")}.`,
          evidence,
          files: input.files,
        }),
      );
    }

    return findings;
  },
};

const JS_REF = /\.(?:c?js|mjs|cjs|ts)$/;
// Shell separators and expansion characters. No token-count or length cap: a cap lets padding push a real script name out.
const TOKEN_SPLIT = /[\s;&|<>()"'`=,${}\\]+/;

/**
 * Resolves local script files named by a lifecycle command. Indexes are built on
 * first use, so a package with no hooks pays nothing. Work is linear in total
 * path length: exact paths through a Map, JS suffix matches through a basename
 * bucket (never every suffix of every path).
 */
function makeResolver(files: PackageFile[]): (cmd: string) => PackageFile[] {
  let byPath: Map<string, PackageFile> | undefined;
  let byBase: Map<string, PackageFile[]> | undefined;
  const exact = (p: string) => (byPath ??= new Map(files.map((f) => [f.path, f] as const))).get(p);
  const suffix = (ref: string) => {
    if (!byBase) {
      byBase = new Map();
      for (const f of files) {
        const base = f.path.slice(f.path.lastIndexOf("/") + 1);
        (byBase.get(base) ?? byBase.set(base, []).get(base)!).push(f);
      }
    }
    return byBase.get(ref.slice(ref.lastIndexOf("/") + 1))?.find((f) => f.path.endsWith(`/${ref}`));
  };

  return (cmd) => {
    const out = new Set<PackageFile>();
    const seen = new Set<string>();
    for (const t of cmd.split(TOKEN_SPLIT)) {
      const ref = t.replace(/^\.\//, "");
      if (!ref || seen.has(ref)) continue;
      seen.add(ref);
      let hit = exact(`package/${ref}`);
      // Node resolves `node setup` / `node scripts` as setup.js / scripts/index.js.
      if (!hit && !ref.slice(ref.lastIndexOf("/") + 1).includes(".")) {
        hit = exact(`package/${ref}.js`) ?? exact(`package/${ref}/index.js`);
      }
      hit ??= JS_REF.test(ref) ? suffix(ref) : undefined;
      if (hit) out.add(hit);
    }
    return [...out];
  };
}

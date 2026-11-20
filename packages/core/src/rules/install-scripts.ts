import type { AuditInput, Finding, PackageFile, Rule } from "../types.js";
import { codeFiles, mkFinding, scanLines, truncate } from "./util.js";

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
    const code = codeFiles(input);
    const byPath = new Map(input.files.map((f) => [f.path, f] as const));

    for (const hook of LIFECYCLE) {
      const cmd = scripts[hook];
      if (typeof cmd !== "string" || !cmd) continue; // npm ignores non-string hooks; one must not throw the rule away

      // What does the lifecycle command itself do?
      const inlineDangers = DANGER_IN_SCRIPT.filter((d) => d.re.test(cmd));

      // If it runs a local script file, inspect that file's contents too.
      const referenced = referencedFiles(cmd, code, byPath);
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

const MAX_TOKENS = 64;
const MAX_TOKEN_LEN = 256;
// Docs/data named as an argument (`cat README`, `node -p package.json`) are not executed; scanning them is noise.
const NOT_SCRIPT = /(?:\.(?:md|markdown|json|txt|ya?ml|lock|map)|(?:^|\/)(?:readme|licen[cs]e|changelog|notice))$/i;
const JS_REF = /\.(?:c?js|mjs|cjs|ts)$/;

/**
 * Resolve local script files referenced by a lifecycle command. Every
 * whitespace/shell-separated token that names a retained package file counts
 * (`node setup`, `sh build.sh`, `node scripts/x.js`); JS names also match by
 * path suffix. Tokens are bounded so a huge command stays linear.
 */
function referencedFiles(cmd: string, code: PackageFile[], byPath: Map<string, PackageFile>): PackageFile[] {
  const out = new Set<PackageFile>();
  const tokens = new Set<string>();
  for (const t of cmd.split(/[\s;&|<>()"'`=,]+/)) {
    if (t && t.length <= MAX_TOKEN_LEN) tokens.add(t.replace(/^\.\//, ""));
    if (tokens.size >= MAX_TOKENS) break;
  }
  for (const ref of tokens) {
    const hit = byPath.get(`package/${ref}`) ?? (JS_REF.test(ref) ? code.find((f) => f.path.endsWith(`/${ref}`)) : undefined);
    if (hit && !NOT_SCRIPT.test(hit.path)) out.add(hit);
  }
  return [...out];
}

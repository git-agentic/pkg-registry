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

    for (const hook of LIFECYCLE) {
      const cmd = scripts[hook];
      if (!cmd) continue;

      // What does the lifecycle command itself do?
      const inlineDangers = DANGER_IN_SCRIPT.filter((d) => d.re.test(cmd));

      // If it runs a local script file, inspect that file's contents too.
      const referenced = referencedFiles(cmd, code);
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

/** Resolve local script files referenced by a lifecycle command (e.g. `node scripts/x.js`). */
function referencedFiles(cmd: string, code: PackageFile[]): PackageFile[] {
  const out: PackageFile[] = [];
  const re = /([\w./-]+\.(?:c?js|mjs|cjs|ts))/g;
  for (const m of cmd.matchAll(re)) {
    const ref = (m[1] ?? "").replace(/^\.\//, "");
    const hit = code.find((f) => f.path === `package/${ref}` || f.path.endsWith(`/${ref}`));
    if (hit) out.push(hit);
  }
  return out;
}

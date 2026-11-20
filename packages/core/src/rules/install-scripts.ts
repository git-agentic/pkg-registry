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
    const bySuffix = suffixIndex(code);

    for (const hook of LIFECYCLE) {
      const cmd = scripts[hook];
      if (typeof cmd !== "string" || !cmd) continue; // npm ignores non-string hooks; one must not throw the rule away

      // What does the lifecycle command itself do?
      const inlineDangers = DANGER_IN_SCRIPT.filter((d) => d.re.test(cmd));

      // If it runs a local script file, inspect that file's contents too.
      const referenced = referencedFiles(cmd, byPath, bySuffix);
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

// Docs/data named as an argument (`cat README`, `node -p package.json`) are not executed; scanning them is noise.
const NOT_SCRIPT = /(?:\.(?:md|markdown|json|txt|ya?ml|lock|map)|(?:^|\/)(?:readme|licen[cs]e|changelog|notice))$/i;
const JS_REF = /\.(?:c?js|mjs|cjs|ts)$/;
// Shell separators and expansion characters. No token-count or length cap: a cap lets padding push a real script name out.
const TOKEN_SPLIT = /[\s;&|<>()"'`=,${}\\]+/;

/** Every `/`-suffix of each code path (`a/b.js` → `b.js`), first file wins, so a suffix match is one lookup. */
function suffixIndex(code: PackageFile[]): Map<string, PackageFile> {
  const m = new Map<string, PackageFile>();
  for (const f of code) {
    for (let i = f.path.indexOf("/"); i !== -1; i = f.path.indexOf("/", i + 1)) {
      const suffix = f.path.slice(i + 1);
      if (!m.has(suffix)) m.set(suffix, f);
    }
  }
  return m;
}

/**
 * Resolve local script files referenced by a lifecycle command. Every
 * shell-separated token that names a retained package file counts (`node setup`,
 * `sh build.sh`, `node scripts/x.js`); JS names also match by path suffix.
 * One linear pass plus Map lookups, whatever the command length.
 */
function referencedFiles(cmd: string, byPath: Map<string, PackageFile>, bySuffix: Map<string, PackageFile>): PackageFile[] {
  const out = new Set<PackageFile>();
  const seen = new Set<string>();
  for (const t of cmd.split(TOKEN_SPLIT)) {
    const ref = t.replace(/^\.\//, "");
    if (!ref || seen.has(ref)) continue;
    seen.add(ref);
    const hit = byPath.get(`package/${ref}`) ?? (JS_REF.test(ref) ? bySuffix.get(ref) : undefined);
    if (hit && !NOT_SCRIPT.test(hit.path)) out.add(hit);
  }
  return [...out];
}

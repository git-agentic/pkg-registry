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
// Pieces of a shell word that may hide a path (`${VAR}setup`, `--require=./x.js`, `a\b`).
const WORD_PIECES = /[${}\\=,'"`()]+/;
const SIMPLE_COMMAND_SPLIT = /&&|\|\||[;|&\n]/;

/** Split on `&&`, `||`, `;`, `|`, `&`, newline outside quotes. An unterminated quote falls back to the plain split. */
function splitSimpleCommands(cmd: string): string[] {
  const out: string[] = [];
  let start = 0;
  let quote = "";
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (c === "\\" && quote !== "'") { i++; continue; }
    if (quote) { if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === ";" || c === "|" || c === "&" || c === "\n") {
      out.push(cmd.slice(start, i));
      while (cmd[i + 1] === c && c !== ";" && c !== "\n") i++; // `&&`, `||`
      start = i + 1;
    }
  }
  if (quote) return cmd.split(SIMPLE_COMMAND_SPLIT);
  out.push(cmd.slice(start));
  return out;
}
const WRAPPERS = new Set(["env", "exec", "nohup", "time", "command", "npx"]);
// Inline-code flags differ per interpreter (`sh -e` is errexit, not inline code).
const SHELL_INLINE = /^-[a-z]*c[a-z]*$/i; // `-c`, `-ec`, `-lc`
const NODE_INLINE = /^(?:-[ep]|-pe|--eval(?:=.*)?|--print(?:=.*)?)$/;
const INLINE_FLAG: Record<string, RegExp> = {
  sh: SHELL_INLINE, bash: SHELL_INLINE, zsh: SHELL_INLINE, dash: SHELL_INLINE, ksh: SHELL_INLINE,
  node: NODE_INLINE, nodejs: NODE_INLINE, bun: NODE_INLINE, deno: NODE_INLINE,
  python: /^-c$/, python3: /^-c$/, perl: /^-e$/, ruby: /^-e$/, php: /^-r$/,
  pwsh: /^-(?:c|command)$/i, powershell: /^-(?:c|command)$/i,
};
// Operands with these extensions are code wherever they appear (`sudo node x.js`, `timeout 5 sh x.sh`).
const CODE_WORD = /\.(?:c?js|mjs|ts|sh|py|pl|rb)\b/i;
// Flags whose value is also executed code (`node -r ./hook main.js`).
const CODE_VALUE_FLAG = /^--?(?:r|require|import|loader|experimental-loader)(?:=(.*))?$/;
const MAX_SUFFIX_DEPTH = 64;

interface TrieNode {
  kids: Map<string, TrieNode>;
  first?: PackageFile;
}

/**
 * Resolves the local files a lifecycle command actually EXECUTES: per simple
 * command, the command word (`./setup`) or, for an interpreter (`node`, `sh`, ...),
 * the first operand that names a package file. Data arguments (`node gen.js README.md`)
 * are not scanned. Indexes are built on first use, so a package with no hooks pays
 * nothing, and all work is linear in the command and total path length: exact paths
 * through a Map, JS suffixes through a reverse component trie (O(token components)).
 */
function makeResolver(files: PackageFile[]): (cmd: string) => PackageFile[] {
  let byPath: Map<string, PackageFile> | undefined;
  let trie: TrieNode | undefined;
  const exact = (p: string) => (byPath ??= new Map(files.map((f) => [f.path, f] as const))).get(p);
  const suffix = (ref: string) => {
    if (!trie) {
      const root: TrieNode = { kids: new Map() };
      for (const f of files) {
        const comps = f.path.split("/");
        let node = root;
        // Depth d holds files with more than d components, so `endsWith("/" + ref)` needs a longer path.
        for (let d = 1; d < comps.length && d <= MAX_SUFFIX_DEPTH; d++) {
          const key = comps[comps.length - d]!;
          let next = node.kids.get(key);
          if (!next) node.kids.set(key, (next = { kids: new Map() }));
          next.first ??= f;
          node = next;
        }
      }
      trie = root;
    }
    const comps = ref.split("/");
    if (comps.length > MAX_SUFFIX_DEPTH) return undefined;
    let node: TrieNode | undefined = trie;
    for (let i = comps.length - 1; i >= 0 && node; i--) node = node.kids.get(comps[i]!);
    return node?.first;
  };

  const resolveRef = (raw: string): PackageFile | undefined => {
    const ref = raw.replace(/^\.\//, "");
    if (!ref) return undefined;
    let hit = exact(`package/${ref}`);
    // Node resolves `node setup` / `node scripts` as setup.js / scripts/index.js.
    if (!hit && !ref.slice(ref.lastIndexOf("/") + 1).includes(".")) {
      hit = exact(`package/${ref}.js`) ?? exact(`package/${ref}/index.js`);
    }
    return hit ?? (JS_REF.test(ref) ? suffix(ref) : undefined);
  };
  const resolveWord = (word: string): PackageFile | undefined => {
    const w = trimPunct(word);
    const direct = resolveRef(w);
    if (direct) return direct;
    for (const piece of w.split(WORD_PIECES)) {
      const hit = resolveRef(piece);
      if (hit) return hit;
    }
    return undefined;
  };
  const isPrefix = (words: string[], i: number) =>
    /^[A-Za-z_]\w*=/.test(words[i]!) || WRAPPERS.has(words[i]!) || (i > 0 && WRAPPERS.has(words[i - 1]!) && words[i]!.startsWith("-"));

  /** Scan one command line; `sh -c "<code>"` code is scanned again as a command line (depth-bounded, so linear). */
  const scan = (cmd: string, out: Set<PackageFile>, depth: number): void => {
    for (const simple of splitSimpleCommands(cmd)) {
      const rawWords = simple.split(/\s+/).filter(Boolean);
      const words = rawWords.map(unquote);
      let i = 0;
      while (i < words.length && isPrefix(words, i)) i++;
      const command = words[i];
      if (!command) continue;
      const name = trimPunct(command);
      const interpreter = name.slice(name.lastIndexOf("/") + 1);
      const inline = Object.hasOwn(INLINE_FLAG, interpreter) ? INLINE_FLAG[interpreter] : undefined;
      // The command word itself may be a package script (`./setup`).
      if (!inline) {
        const hit = resolveWord(command);
        if (hit) out.add(hit);
      }
      // Operands: anything with a code extension is scanned wherever it sits (unknown wrappers like
      // `sudo`/`timeout`/`xargs` must not hide it). For an interpreter, the first other operand that
      // names a package file is also the executed script (earlier operands may be flag values).
      let found = false;
      for (let j = i + 1; j < words.length; j++) {
        const w = words[j]!;
        if (inline && w.startsWith("-")) {
          if (inline.test(w)) {
            found = true; // later extension-less operands are arguments to that inline code, not scripts
            let code = w.includes("=") ? w.slice(w.indexOf("=") + 1) : "";
            if (!w.includes("=")) {
              // Quoted code may span several whitespace-split words: find the span on the RAW words
              // (unquoting first would hide the opening quote). No closing quote ⇒ only one word.
              const first = rawWords[j + 1] ?? "";
              const q = first[0] === "'" || first[0] === '"' ? first[0] : "";
              let end = j + 1;
              if (q && !(first.length > 1 && first.endsWith(q))) {
                for (let k = j + 2; k < rawWords.length; k++) {
                  if (rawWords[k]!.endsWith(q)) { end = k; break; }
                }
              }
              code = rawWords.slice(j + 1, end + 1).join(" ");
              j = end;
            }
            code = unquote(code);
            if (inline === SHELL_INLINE && depth < MAX_INLINE_DEPTH) scan(code, out, depth + 1);
            else {
              // Non-shell inline code (`node -e "require('./x.js')"`): code-extension names inside still count.
              for (const cw of code.split(/\s+/)) {
                const hit = CODE_WORD.test(cw) ? resolveWord(cw) : undefined;
                if (hit) out.add(hit);
              }
            }
            continue;
          }
          const m = CODE_VALUE_FLAG.exec(w);
          const value = m ? (m[1] ?? words[++j]) : undefined;
          const hit = value ? resolveWord(value) : undefined;
          if (hit) out.add(hit);
          continue;
        }
        const isCode = CODE_WORD.test(w);
        if (!isCode && (!inline || found)) continue;
        const hit = resolveWord(w);
        if (hit) {
          out.add(hit);
          if (inline) found = true;
        }
      }
    }
  };

  return (cmd) => {
    const out = new Set<PackageFile>();
    scan(cmd, out, 0);
    return [...out];
  };
}

const MAX_INLINE_DEPTH = 3;
const isPunct = (c: string | undefined) => c === "(" || c === ")" || c === '"' || c === "'" || c === "`";

/** Trim quote/paren punctuation from both ends with two pointers (a `)+$` regex is quadratic on `)))…x`). */
function trimPunct(w: string): string {
  let i = 0;
  let j = w.length;
  while (i < j && isPunct(w[i])) i++;
  while (j > i && isPunct(w[j - 1])) j--;
  return w.slice(i, j);
}

/** Strip one pair of matching surrounding quotes (`'node'` → `node`). */
function unquote(w: string): string {
  const q = w[0];
  return w.length >= 2 && (q === "'" || q === '"' || q === "`") && w[w.length - 1] === q ? w.slice(1, -1) : w;
}

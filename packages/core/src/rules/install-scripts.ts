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
    const referencedFiles = makeResolver(input.files, scripts);

    for (const hook of LIFECYCLE) {
      const cmd = scripts[hook];
      if (typeof cmd !== "string" || !cmd) continue; // npm ignores non-string hooks; one must not throw the rule away

      // If it runs a local script file or a package script, inspect those too.
      const { files: referenced, scripts: followed } = referencedFiles(cmd);

      // What does the lifecycle command itself do? Followed script bodies get the same check.
      const inlineDangers = DANGER_IN_SCRIPT.filter((d) => d.re.test(cmd));
      const followedDangers = followed.flatMap(([name, body]) =>
        DANGER_IN_SCRIPT.filter((d) => d.re.test(body)).map((d) => ({
          why: d.why,
          ev: { file: "package/package.json", snippet: `"${name}": "${truncate(body, 120)}"` },
        })),
      );
      const fileDangers = referenced.flatMap((f) =>
        DANGER_IN_SCRIPT.flatMap((d) =>
          scanLines(f, d.re, 2).map((ev) => ({ why: d.why, ev })),
        ),
      );

      if (inlineDangers.length === 0 && fileDangers.length === 0 && followedDangers.length === 0) {
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
        ...new Set([...inlineDangers, ...followedDangers, ...fileDangers].map((d) => d.why)),
      ];
      const evidence = [
        { file: "package/package.json", snippet: `"${hook}": "${truncate(cmd, 120)}"` },
        ...followedDangers.map((d) => d.ev),
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

// Pieces of a shell word that may hide a path (`${VAR}setup`, `--require=./x.js`, `a\b`).
const WORD_PIECES = /[${}\\=,'"`()<>]+/; // `<>`: `node <setup.js` reads setup.js
const SIMPLE_COMMAND_SPLIT = /&&|\|\||[;|&\n]/;
const PIPELINE_SPLIT = /&&|\|\||[;\n]|(?<!\|)&/; // like SIMPLE_COMMAND_SPLIT, but a single `|` or `|&` stays inside the pipeline

/**
 * Split on `&&`, `||`, `;`, `|`, `&`, newline outside quotes (`keepPipes`: a single `|` does not split, giving
 * pipelines). An unterminated quote falls back to the plain split.
 */
function splitSimpleCommands(cmd: string, keepPipes = false): string[] {
  const out: string[] = [];
  let start = 0;
  let quote = "";
  let pipeEnd = -1; // index of the last char of the last unquoted, unescaped `|` / `|&`
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (c === "\\" && quote !== "'") { i++; continue; }
    if (quote) { if (c === quote) quote = ""; continue; }
    if (c === "'" || c === '"') { quote = c; continue; }
    if (c === "|" && keepPipes && cmd[i + 1] !== "|") { if (cmd[i + 1] === "&") i++; pipeEnd = i; continue; }
    if (c === "\n" && keepPipes) { // a newline right after a pipe operator continues the pipeline
      let j = i - 1;
      while (j >= start && (cmd[j] === " " || cmd[j] === "\t")) j--;
      if (j === pipeEnd) continue;
    }
    if (c === ";" || c === "|" || c === "&" || c === "\n") {
      out.push(cmd.slice(start, i));
      while (cmd[i + 1] === c && c !== ";" && c !== "\n") i++; // `&&`, `||`
      start = i + 1;
    }
  }
  if (quote) return cmd.split(keepPipes ? PIPELINE_SPLIT : SIMPLE_COMMAND_SPLIT);
  out.push(cmd.slice(start));
  return out;
}
/**
 * Bodies of the outermost `$(...)` and backtick spans, in one pass (nested ones are reached by the
 * recursive scan). Quotes are ignored on purpose: this only adds coverage.
 */
function substitutionBodies(cmd: string): string[] {
  const bodies: string[] = [];
  let depth = 0;
  let start = 0;
  let tick = -1;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === "\\") { i++; continue; }
    if (c === "`" && depth === 0) {
      if (tick < 0) tick = i + 1;
      else { bodies.push(cmd.slice(tick, i)); tick = -1; }
    } else if (c === "$" && cmd[i + 1] === "(") {
      if (depth++ === 0) start = i + 2;
      i++;
    } else if (c === "(" && depth > 0) depth++;
    else if (c === ")" && depth > 0 && --depth === 0) bodies.push(cmd.slice(start, i));
  }
  return bodies;
}
const WRAPPERS = new Set(["env", "exec", "nohup", "time", "command", "npx", "sudo"]);
// Inline-code flags differ per interpreter (`sh -e` is errexit, not inline code).
const SHELL_INLINE = /^-[a-z]*c[a-z]*$/i; // `-c`, `-ec`, `-lc`
const NODE_INLINE = /^(?:-[ep]|-pe|--eval(?:=.*)?|--print(?:=.*)?)$/;
const NO_INLINE = /(?!)/; // never matches: these interpreters take no inline code
const INLINE_FLAG: Record<string, RegExp> = {
  sh: SHELL_INLINE, bash: SHELL_INLINE, zsh: SHELL_INLINE, dash: SHELL_INLINE, ksh: SHELL_INLINE,
  node: NODE_INLINE, nodejs: NODE_INLINE, bun: NODE_INLINE, deno: NODE_INLINE, tsx: NODE_INLINE, "ts-node": NODE_INLINE,
  ".": NO_INLINE, source: NO_INLINE, // `. ./setup` / `source setup`: the first operand is the sourced script
  python: /^-c$/, python3: /^-c$/, perl: /^-e$/, ruby: /^-e$/, php: /^-r$/,
  pwsh: /^-(?:c|command)$/i, powershell: /^-(?:c|command)$/i,
};
// Operands with these extensions are code wherever they appear (`sudo node x.js`, `timeout 5 sh x.sh`).
const CODE_WORD = /\.(?:c?js|mjs|m?ts|cts|sh|py|pl|rb)\b/i;
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
function makeResolver(files: PackageFile[], scripts: Record<string, string>): (cmd: string) => { files: PackageFile[]; scripts: [string, string][] } {
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

  /**
   * `exact`: only `package/<ref>` (a bare command word such as `echo` or `node-gyp`).
   * `path`: also the suffix trie (a command word written with a `/`, e.g. `./setup` after `cd scripts`).
   * `script`: an executed operand, with Node-style `.js` / `/index.js` retries and the suffix trie.
   * A shell never appends `.js` to a command word, so only `script` retries.
   */
  type Mode = "exact" | "path" | "script";
  // `node <dir>`: the `main` file of <dir>/package.json, then <dir>/index.js. Resolved (or missed) once per directory.
  const entries = new Map<string, PackageFile | null>();
  const entry = (dir: string): PackageFile | undefined => {
    let hit = entries.get(dir);
    if (hit === undefined) {
      let main: unknown;
      try { main = JSON.parse(exact(`${dir}/package.json`)?.content ?? "null")?.main; } catch { /* no usable main */ }
      const m = typeof main === "string" ? main.replace(/^\.\//, "") : "";
      hit = (m ? exact(`${dir}/${m}`) ?? exact(`${dir}/${m}.js`) ?? exact(`${dir}/${m}/index.js`) : undefined) ?? exact(`${dir}/index.js`) ?? null;
      entries.set(dir, hit);
    }
    return hit ?? undefined;
  };
  let spill: PackageFile[] = []; // extra candidates a resolution found besides the one it returned
  const spillAll = (hits: (PackageFile | undefined)[]): PackageFile | undefined => {
    const [first, ...rest] = new Set(hits.filter((f): f is PackageFile => !!f));
    for (const f of rest) spill.push(f);
    return first;
  };
  // Bare module names resolve inside the tarball only (never the host or network). Over-follow: the spec as a file
  // (`.js`/`.mjs`/`.cjs`), the package main / index.js, and every string target of the package's `exports`.
  const exportTargets = new Map<string, string[]>();
  const targetsOf = (pkgDir: string): string[] => {
    let t = exportTargets.get(pkgDir);
    if (!t) {
      t = [];
      let exp: unknown;
      try { exp = JSON.parse(exact(`${pkgDir}/package.json`)?.content ?? "null")?.exports; } catch { /* no exports */ }
      for (let stack: unknown[] = [exp], seen = 0; stack.length && seen < 1000; seen++) { // node bound
        const v = stack.pop();
        if (typeof v === "string") { const n = normalizeRel(v); if (n) t.push(n); }
        else if (v && typeof v === "object") for (const c of Object.values(v)) stack.push(c);
      }
      exportTargets.set(pkgDir, t);
    }
    return t;
  };
  const modules = new Map<string, (PackageFile | undefined)[]>();
  const resolveModule = (spec: string): (PackageFile | undefined)[] => {
    let hits = modules.get(spec);
    if (!hits) {
      const m = `package/node_modules/${spec}`;
      const pkg = `package/node_modules/${spec.split("/").slice(0, spec.startsWith("@") ? 2 : 1).join("/")}`;
      hits = [exact(m), exact(`${m}.js`), exact(`${m}.mjs`), exact(`${m}.cjs`), entry(m), ...targetsOf(pkg).map((t) => exact(`${pkg}/${t}`))];
      modules.set(spec, hits);
    }
    return hits;
  };
  // Every file a bundled package's `bin` (a string or an object) points at, per command name, plus `node_modules/.bin/<name>`.
  // The map is built once on first use; targets are exact normalized paths, in any tar order.
  let bins: Map<string, Set<PackageFile>> | undefined;
  const bundledBins = (name: string): (PackageFile | undefined)[] => {
    if (!bins) {
      bins = new Map();
      for (const f of files) {
        const pkg = /^package\/node_modules\/((?:@[^/]+\/)?[^/]+)\/package\.json$/.exec(f.path)?.[1];
        if (!pkg || pkg.split("/").some((c) => c.length > 214)) continue; // npm names are at most 214 chars
        let bin: unknown;
        try { bin = JSON.parse(f.content)?.bin; } catch { continue; }
        const map: Record<string, unknown> = typeof bin === "string" ? { [pkg.slice(pkg.lastIndexOf("/") + 1)]: bin } : bin && typeof bin === "object" ? (bin as Record<string, unknown>) : {};
        for (const [n, rel] of Object.entries(map)) {
          const r = typeof rel === "string" ? normalizeRel(rel) : undefined;
          const hit = r ? exact(`package/node_modules/${pkg}/${r}`) : undefined;
          if (hit) (bins.get(n) ?? bins.set(n, new Set()).get(n)!).add(hit);
        }
      }
    }
    return [...(bins.get(name) ?? []), exact(`package/node_modules/.bin/${name}`)];
  };
  // The file a preload flag value (`-r <value>`) loads: a local path, else a bundled module. The `.js` retry applies
  // even when the basename has a dot (`./hook.prod`).
  const preload = (value: string): PackageFile | undefined => {
    const v = trimPunct(value);
    if (!v) return undefined;
    return spillAll(LOCAL_PATH.test(v)
      ? [resolveWord(v, "script"), v.startsWith("/") ? undefined : exact(`package/${v.replace(/^\.\//, "")}.js`)]
      : resolveModule(v));
  };
  /** Tokens of a `VAR=value` assignment (`NODE_OPTIONS`): recognized preload flags (`-r x`, `--require=x`) and relative code files. */
  const scanOptionTokens = (tokens: string[], out: Set<PackageFile>): void => {
    for (let k = 0; k < tokens.length; k++) {
      const t = trimPunct(tokens[k]!);
      const m = CODE_VALUE_FLAG.exec(t);
      const hit = m ? preload(m[1] ?? tokens[++k] ?? "")
        : spillAll(t.split("=").map((piece) => (CODE_WORD.test(piece) && LOCAL_PATH.test(piece) ? resolveWord(piece, "script") : undefined)));
      if (hit) out.add(hit);
    }
  };
  const resolveRef = (raw: string, mode: Mode): PackageFile | undefined => {
    const ref = raw.replace(/^\.\//, "").replace(/\/$/, "") || (raw === "./" ? "." : "");
    if (!ref) return undefined;
    if (ref === "." && mode === "script") return entry("package");
    let hit = exact(`package/${ref}`);
    if (hit || mode === "exact") return hit;
    if (mode === "path") return suffix(ref);
    const dotted = ref.slice(ref.lastIndexOf("/") + 1).includes(".");
    // After a `cd scripts &&` the file sits deeper than `package/<ref>`.
    const nested = () => suffix(ref) ?? (dotted ? undefined : suffix(`${ref}.js`) ?? suffix(`${ref}.ts`));
    // Node resolves `node setup` / `node scripts` as setup.js / scripts/<main or index.js>; TS runners also try setup.ts.
    if (!dotted) hit = exact(`package/${ref}.js`);
    hit ??= entry(`package/${ref}`); // a directory may have a dot in its name (`tools.v2`)
    if (!dotted) hit ??= exact(`package/${ref}.ts`);
    if (!hit) return nested();
    const n = nested(); // over-follow: a root candidate must not hide a nested file the suffix lookup finds
    if (n && n !== hit) spill.push(n);
    return hit;
  };
  const resolveWord = (word: string, mode: Mode): PackageFile | undefined => {
    const w = trimPunct(word);
    const direct = resolveRef(w, mode);
    if (direct) return direct;
    for (const piece of w.split(WORD_PIECES)) {
      const hit = resolveRef(piece, mode);
      if (hit) return hit;
    }
    return undefined;
  };
  // A command word is judged by its basename (`/usr/bin/env` is `env`). A relative path that names a package file
  // (`./bin/env`) is that file too: it is scanned (`localCommand`) and still plays the wrapper/interpreter role.
  // Path-qualified: exact, then suffix (after a `cd`). Bare: only a wrapper or interpreter name, exact (`tsx` may be `package/tsx`).
  const localCommand = (w: string, direct: boolean): PackageFile | undefined => {
    if (/^(?:[/-]|[A-Za-z_]\w*=)/.test(w)) return undefined; // not a flag, absolute path or `VAR=value`
    const t = trimPunct(w);
    if (w.includes("/")) return resolveWord(t, "path");
    const own = WRAPPERS.has(t) || Object.hasOwn(INLINE_FLAG, t) ? exact(`package/${t}`) : undefined;
    // A shell builtin in direct command position never runs a bundled bin; behind `env`/`sudo`/... it does.
    return spillAll([own, ...(direct && SHELL_BUILTINS.has(t) ? [] : bundledBins(t))]);
  };
  const isPrefix = (words: string[], i: number) =>
    /^[A-Za-z_]\w*=/.test(words[i]!) || WRAPPERS.has(base(trimPunct(words[i]!))) || (i > 0 && WRAPPERS.has(base(trimPunct(words[i - 1]!))) && words[i]!.startsWith("-"));
  const isInterpreterCommand = (simple: string): boolean => {
    const ws = simple.split(/\s+/).filter(Boolean).map(unquote);
    let k = 0;
    while (k < ws.length && isPrefix(ws, k)) k++;
    return ws[k] !== undefined && Object.hasOwn(INLINE_FLAG, base(trimPunct(ws[k]!)));
  };

  // Package scripts reached from a command line, scanned from a worklist (not recursion): each name once, so
  // the work is bounded by the number of scripts and a long chain cannot overflow the stack.
  let visited = new Set<string>();
  let queue: [string, string][] = [];
  const enqueue = (n: string) => {
    const body = Object.hasOwn(scripts, n) ? scripts[n] : undefined;
    if (typeof body === "string" && !visited.has(n)) { visited.add(n); queue.push([n, body]); }
  };
  /**
   * Deliberate over-following: after `npm`/`pnpm`/`yarn`/`bun`, every word is treated as a script name, and
   * so is each script a built-in command of that name runs (`PM_COMMANDS`). Each gets its `pre`/`post` scripts.
   * Undefined names are skipped by `enqueue`. A script that does not run costs a false positive only if it is
   * itself dangerous; missing one that runs is a bypass.
   */
  const followScriptWords = (words: string[], from: number, out: Set<PackageFile>): void => {
    // Any package-manager invocation may run the install lifecycle (`npm ci`, bare `yarn`, an alias nobody listed).
    for (const n of INSTALL_SCRIPTS) { enqueue(`pre${n}`); enqueue(n); enqueue(`post${n}`); } // npm runs preprepare/postprepare too
    for (let j = from; j < words.length; j++) {
      const w = words[j]!;
      for (const x of [w, ...(PM_COMMANDS.get(w) ?? [])]) {
        enqueue(`pre${x}`);
        enqueue(x);
        enqueue(`post${x}`);
      }
      // `npm start` with no `start` script runs `node server.js`.
      if ((w === "start" || w === "restart") && !(Object.hasOwn(scripts, "start") && typeof scripts.start === "string" && scripts.start !== "")) {
        const hit = exact("package/server.js");
        if (hit) out.add(hit);
      }
    }
  };

  /**
   * Scan one command line; `sh -c "<code>"` code is scanned again as a command line (depth-bounded, so linear).
   */
  const scan = (cmd: string, out: Set<PackageFile>, depth: number): void => {
    // Quote tracking can only ADD coverage: a stray apostrophe (`# it's`) must not hide later commands,
    // so the plain split is scanned too, and `$(...)` / backtick bodies are scanned as command lines.
    if (depth < MAX_INLINE_DEPTH) for (const body of substitutionBodies(cmd)) scan(body, out, depth + 1);
    for (const pipeline of new Set([...splitSimpleCommands(cmd, true), ...cmd.split(PIPELINE_SPLIT)])) {
    const quoted = splitSimpleCommands(pipeline); // quote-aware, so `php -r 'a;b' README` is one stage
    const stages = new Set([...quoted, ...pipeline.split(SIMPLE_COMMAND_SPLIT)]);
    // Over-follow: the operands of every stage upstream of an interpreter stage (`cat x | sh`) are scripts.
    const upstream = new Set(quoted.slice(0, Math.max(0, quoted.map(isInterpreterCommand).lastIndexOf(true))));
    for (const simple of stages) {
      const rawWords = simple.split(/\s+/).filter(Boolean);
      const words = rawWords.map(unquote);
      // Indexes of words ending in each quote char, built once per command so repeated inline flags
      // do not rescan the remaining arguments.
      const closers: Record<string, number[] | undefined> = {};
      const nextClose = (q: string, from: number): number | undefined => {
        const list = (closers[q] ??= rawWords.flatMap((rw, k) => (rw.endsWith(q) ? [k] : [])));
        let lo = 0, hi = list.length;
        while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid]! < from) lo = mid + 1; else hi = mid; }
        return list[lo];
      };
      let i = 0;
      let viaWrapper = false; // after `env`/`sudo`/... the next word is an external command, never a builtin
      let spanEnd = -1; // last word of the quoted assignment value being spanned: each word is spanned at most once
      for (; i < words.length && isPrefix(words, i); i++) {
        const local = localCommand(words[i]!, !viaWrapper);
        if (local) out.add(local);
        if (EXTERNAL_WRAPPERS.has(base(trimPunct(words[i]!)))) viaWrapper = true;
        // `NODE_OPTIONS=--require=./hook node -v`: preload flags and code files inside an assignment value run too.
        const eq = words[i]!.indexOf("=");
        if (eq < 0) continue;
        let val = words[i]!.slice(eq + 1);
        // `NODE_OPTIONS='-r ./hook'`: a quote left open by the word spans to the next word that ends with it. The
        // spanned words are also read as normal words (no skipping), so spanning only adds coverage.
        const q = i > spanEnd ? openQuote(val) : "";
        const e = q ? nextClose(q, i + 1) : undefined;
        if (e !== undefined) { val += ` ${rawWords.slice(i + 1, e + 1).join(" ")}`; spanEnd = e; }
        scanOptionTokens(unquote(val).split(/\s+/), out);
      }
      const command = words[i];
      if (!command) continue;
      const name = trimPunct(command);
      const interpreter = base(name);
      const local = localCommand(command, !viaWrapper);
      if (local) out.add(local);
      if (PACKAGE_MANAGERS.has(interpreter)) followScriptWords(words, i + 1, out);
      const inline = Object.hasOwn(INLINE_FLAG, interpreter) ? INLINE_FLAG[interpreter] : undefined;
      // The command word itself may be a package script (`./setup`).
      if (!inline) {
        const hit = resolveWord(command, name.includes("/") ? "path" : "exact");
        if (hit) out.add(hit);
      }
      // Operands: anything with a code extension is scanned wherever it sits (unknown wrappers like
      // `sudo`/`timeout`/`xargs` must not hide it). For an interpreter, the first other operand that
      // names a package file is also the executed script (earlier operands may be flag values).
      let found = false;
      for (let j = i + 1; j < words.length; j++) {
        const w = words[j]!;
        // Redirections are not operands. `<file` feeds file to the command (scan it, an interpreter
        // runs it), but it never takes the place of the script operand; `>file` targets are outputs.
        // Detected on the RAW word: a quoted `">x.js"` is a literal file name, not a redirect.
        const redirect = /^(\d*)([<>])[<>&]*(.*)$/.exec(rawWords[j]!);
        if (redirect) {
          const target = unquote(redirect[3] ?? "") || words[++j] || "";
          if (redirect[2] === "<") {
            const hit = resolveWord(target, "script");
            if (hit) out.add(hit);
          }
          continue;
        }
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
              if (q && !(first.length > 1 && first.endsWith(q))) end = nextClose(q, j + 2) ?? end;
              code = rawWords.slice(j + 1, end + 1).join(" ");
              j = end;
            }
            code = unquote(code);
            if (inline === SHELL_INLINE && depth < MAX_INLINE_DEPTH) scan(code, out, depth + 1);
            else {
              // Non-shell inline code (`node -e "require('./x.js')"`): code-extension names inside still count.
              for (const cw of code.split(/\s+/)) {
                const hit = CODE_WORD.test(cw) ? resolveWord(cw, "script") : undefined;
                if (hit) out.add(hit);
              }
            }
            continue;
          }
          const m = CODE_VALUE_FLAG.exec(w);
          // Any other `--flag=value` (`--test-reporter=./r.js`) counts when its value is a code file.
          const eq = w.indexOf("=");
          const generic = !m && eq > 0 && CODE_WORD.test(w.slice(eq + 1)) ? w.slice(eq + 1) : undefined;
          const value = m ? (m[1] ?? words[++j]) : generic;
          // A bare specifier (`dotenv/config`) is a bundled node_modules module, resolved inside the tarball only.
          const hit = value && (m || LOCAL_PATH.test(value)) ? preload(value) : undefined;
          if (hit) out.add(hit);
          continue;
        }
        const isCode = CODE_WORD.test(w);
        if (!isCode && !(upstream.has(simple) && !inline) && (!inline || found)) continue;
        const hit = resolveWord(w, "script");
        if (hit) {
          out.add(hit);
          if (inline) found = true;
        }
      }
    }
    }
  };

  return (cmd) => {
    const out = new Set<PackageFile>();
    visited = new Set();
    queue = [];
    spill = [];
    scan(cmd, out, 0);
    for (let q = 0; q < queue.length; q++) scan(queue[q]![1], out, 0); // the queue grows while it is read
    for (const f of spill) out.add(f);
    return { files: [...out], scripts: queue };
  };
}

const MAX_INLINE_DEPTH = 3;
const LOCAL_PATH = /^(?:\.{1,2}\/|\/)/;
// Wrappers that exec an external program: `env echo` runs a bundled `echo` bin, a bare `echo` is the builtin.
const EXTERNAL_WRAPPERS = new Set(["env", "exec", "nohup", "sudo", "npx", "xargs"]);
const SHELL_BUILTINS = new Set([
  ":", ".", "[", "alias", "bg", "break", "cd", "command", "continue", "declare", "dirs", "echo", "eval", "exec", "exit", "export",
  "false", "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local", "popd", "printf", "pushd", "pwd", "read",
  "readonly", "return", "set", "shift", "source", "test", "time", "times", "trap", "true", "type", "typeset", "ulimit", "umask",
  "unalias", "unset", "wait",
]);

/** The quote character a shell word leaves open (`'-r`), counting unescaped quotes; "" when balanced. */
function openQuote(w: string): string {
  let q = "";
  for (let i = 0; i < w.length; i++) {
    const c = w[i]!;
    if (c === "\\" && q !== "'") i++;
    else if (q) { if (c === q) q = ""; }
    else if (c === "'" || c === '"') q = c;
  }
  return q;
}

/** A declared relative path as npm normalizes it (`./a/../b` -> `b`); undefined when empty or it climbs out (`..`). */
function normalizeRel(rel: string): string | undefined {
  const out: string[] = [];
  for (const seg of rel.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { if (!out.pop()) return undefined; } else out.push(seg);
  }
  return out.join("/") || undefined;
}
const base = (w: string) => w.slice(w.lastIndexOf("/") + 1);
const PACKAGE_MANAGERS = new Set(["npm", "pnpm", "yarn", "bun"]);
// Scripts a built-in package-manager command runs besides the script of its own name (npm lifecycle).
const INSTALL_SCRIPTS = ["preinstall", "install", "postinstall", "prepublish", "prepare"];
const PM_COMMANDS = new Map<string, string[]>([
  ...["t", "tst"].map((c) => [c, ["test"]] as [string, string[]]),
  // Install scripts are followed for every package-manager command, so install aliases need no entry.
  ...["it", "install-test", "cit", "install-ci-test", "clean-install-test", "sit"].map((c) => [c, ["test"]] as [string, string[]]),
  ["restart", ["restart", "stop", "start"]],
  ["pack", ["prepack", "prepare", "postpack"]],
  ["publish", ["prepublishOnly", "prepack", "prepare", "postpack", "publish", "postpublish"]],
  ...["version", "verison"].map((c) => [c, ["preversion", "version", "postversion"]] as [string, string[]]),
]);
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

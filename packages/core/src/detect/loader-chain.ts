import * as acorn from "acorn";
import * as walk from "acorn-walk";

export interface LoaderPrimitive { stage: "read" | "decode" | "write" | "launch"; line: number; snippet: string }
export interface LoaderBoosters { tempOrHidden: boolean; chmod: boolean; detached: boolean; unref: boolean; moduleLoad: boolean }
export interface LoaderAnalysis { primitives: LoaderPrimitive[]; correlated: boolean; boosters: LoaderBoosters; parseFailed: boolean }

const READ_FNS = new Set(["readFile", "readFileSync", "createReadStream"]);
const DECODE_FNS = new Set(["gunzip", "gunzipSync", "inflate", "inflateSync", "inflateRaw", "inflateRawSync", "brotliDecompress", "brotliDecompressSync", "unzip", "unzipSync"]);
const WRITE_FNS = new Set(["writeFile", "writeFileSync", "createWriteStream", "cp", "cpSync", "copyFile", "copyFileSync"]);
const LAUNCH_FNS = new Set(["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync"]);

/** Bounded, deterministic taint tags a variable can carry. */
type Tag = "read" | "decoded" | "written-path";

function calleeName(node: any): string | null {
  if (node.type === "MemberExpression" && node.property?.type === "Identifier") return node.property.name;
  if (node.type === "Identifier") return node.name;
  return null;
}
function lineOf(src: string, pos: number): number { return src.slice(0, pos).split("\n").length; }
function snip(src: string, node: any): string {
  const s = src.slice(node.start, node.end).replace(/\s+/g, " ");
  return s.length > 160 ? s.slice(0, 159) + "…" : s;
}
/** Names referenced by identifiers anywhere inside a node (bounded read of the subtree). */
function idsIn(node: any): Set<string> {
  const out = new Set<string>();
  walk.full(node, (n: any) => { if (n.type === "Identifier") out.add(n.name); });
  return out;
}

/**
 * Analyze a JS source for a packaged-payload materialization chain. `correlated`
 * requires bounded local dataflow: a launched target taint-reachable from a
 * packaged READ through DECODE then WRITE, following simple assignments/aliases.
 * Parse failure (TS/JSX/other non-JS) → parseFailed:true; the caller falls back
 * to a regex signal capped below critical.
 */
export function analyzeLoaderChain(source: string, opts: { moduleLoadReachable?: boolean } = {}): LoaderAnalysis {
  let ast: any;
  try {
    ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "module", allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowHashBang: true });
  } catch {
    try {
      ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "script", allowReturnOutsideFunction: true, allowHashBang: true });
    } catch {
      return { primitives: [], correlated: false, boosters: { tempOrHidden: false, chmod: false, detached: false, unref: false, moduleLoad: false }, parseFailed: true };
    }
  }

  const primitives: LoaderPrimitive[] = [];
  const taint = new Map<string, Set<Tag>>();          // var name -> tags
  const addTag = (name: string, t: Tag) => { (taint.get(name) ?? taint.set(name, new Set()).get(name)!).add(t); };
  const hasTag = (names: Set<string>, t: Tag): boolean => [...names].some((n) => taint.get(n)?.has(t));

  const boosters: LoaderBoosters = { tempOrHidden: false, chmod: false, detached: false, unref: false, moduleLoad: false };
  let sawDecode = false;
  let correlated = false;

  // Pass 1: propagate simple aliases `const a = b;` so tags flow across copies.
  // Bounded: one linear pass over declarations + assignments; the classifier
  // passes below re-read tags as they are set in source order.
  const record = (stage: LoaderPrimitive["stage"], node: any) =>
    primitives.push({ stage, line: lineOf(source, node.start), snippet: snip(source, node) });

  // Declaration initializer per variable name, so a path built in one statement
  // (e.g. `const out = path.join(os.tmpdir(), ...)`) can still be recognized as
  // temp/hidden when it's later referenced by identifier at the write call site.
  const declInit = new Map<string, any>();

  const isTempOrHidden = (node: any): boolean => {
    const resolved = node.type === "Identifier" ? (declInit.get(node.name) ?? node) : node;
    const txt = source.slice(resolved.start, resolved.end);
    return /tmpdir\s*\(\s*\)|['"`]\/tmp\b|['"`]\.[A-Za-z0-9_]/.test(txt) || /os\.tmpdir/.test(txt);
  };

  walk.ancestor(ast, {
    VariableDeclarator(node: any) {
      if (!node.id || node.id.type !== "Identifier" || !node.init) return;
      const name = node.id.name;
      declInit.set(name, node.init);
      // alias copy
      if (node.init.type === "Identifier") {
        for (const t of taint.get(node.init.name) ?? []) addTag(name, t);
      }
      if (node.init.type === "CallExpression") {
        const fn = calleeName(node.init.callee);
        const args = node.init.arguments ?? [];
        if (fn && READ_FNS.has(fn)) {
          if (!primitives.some((p) => p.stage === "read" && p.line === lineOf(source, node.init.start))) record("read", node.init);
          addTag(name, "read");
        } else if (fn && DECODE_FNS.has(fn)) {
          if (!primitives.some((p) => p.stage === "decode" && p.line === lineOf(source, node.init.start))) record("decode", node.init);
          sawDecode = true;
          if (args.some((a: any) => hasTag(idsIn(a), "read"))) addTag(name, "decoded");
        }
      }
    },
    AssignmentExpression(node: any) {
      if (node.left.type !== "Identifier" || node.operator !== "=") return;
      const name = node.left.name;
      if (node.right.type === "Identifier") {
        for (const t of taint.get(node.right.name) ?? []) addTag(name, t);
        return;
      }
      if (node.right.type === "CallExpression") {
        const fn = calleeName(node.right.callee);
        const args = node.right.arguments ?? [];
        if (fn && READ_FNS.has(fn)) {
          if (!primitives.some((p) => p.stage === "read" && p.line === lineOf(source, node.right.start))) record("read", node.right);
          addTag(name, "read");
        } else if (fn && DECODE_FNS.has(fn)) {
          if (!primitives.some((p) => p.stage === "decode" && p.line === lineOf(source, node.right.start))) record("decode", node.right);
          sawDecode = true;
          if (args.some((a: any) => hasTag(idsIn(a), "read"))) addTag(name, "decoded");
        }
      }
    },
    CallExpression(node: any) {
      const fn = calleeName(node.callee);
      if (!fn) return;
      const args = node.arguments ?? [];
      if (READ_FNS.has(fn) && node.callee.type === "MemberExpression") {
        // reads not captured into a var still count as a READ primitive
        if (!primitives.some((p) => p.stage === "read" && p.line === lineOf(source, node.start))) record("read", node);
      } else if (DECODE_FNS.has(fn)) {
        if (!primitives.some((p) => p.stage === "decode" && p.line === lineOf(source, node.start))) { record("decode", node); sawDecode = true; }
      } else if (WRITE_FNS.has(fn)) {
        // writeFile(path, data): if data is decoded (or read) AND a decode happened,
        // tag the path expression's identifiers as written-path.
        const [pathArg, dataArg] = args;
        record("write", node);
        const dataTainted = dataArg ? (hasTag(idsIn(dataArg), "decoded") || hasTag(idsIn(dataArg), "read")) : false;
        if (pathArg && sawDecode && dataTainted && pathArg.type === "Identifier") {
          addTag(pathArg.name, "written-path");
        }
        if (pathArg && isTempOrHidden(pathArg)) boosters.tempOrHidden = true;
      } else if (fn === "chmod" || fn === "chmodSync") {
        boosters.chmod = true;
        record("write", node);
      } else if (LAUNCH_FNS.has(fn)) {
        record("launch", node);
        const target = args[0];
        if (target && hasTag(idsIn(target), "written-path")) correlated = true;
        // detached / ignored-stdio booster
        const optsArg = args.find((a: any) => a?.type === "ObjectExpression");
        if (optsArg) {
          for (const prop of optsArg.properties ?? []) {
            const key = prop.key?.name ?? prop.key?.value;
            if (key === "detached" && prop.value?.value === true) boosters.detached = true;
            if (key === "stdio" && prop.value?.value === "ignore") boosters.detached = true;
          }
        }
      } else if (fn === "unref") {
        boosters.unref = true;
      } else if (fn === "dlopen") {
        // process.dlopen(module, path): only a LAUNCH when path references written output.
        record("launch", node);
        const target = args[1];
        if (target && hasTag(idsIn(target), "written-path")) correlated = true;
      }
    },
  });

  // Module-load reachability booster: chain sits at Program top level or inside a
  // top-level IIFE, AND the caller says the file is entry/bin reachable.
  boosters.moduleLoad = Boolean(opts.moduleLoadReachable) && topLevelExecution(ast);

  return { primitives, correlated, boosters, parseFailed: false };
}

/** True when the program has top-level statements or a top-level IIFE (executes on import). */
function topLevelExecution(ast: any): boolean {
  for (const stmt of ast.body ?? []) {
    if (stmt.type === "ExpressionStatement") {
      const e = stmt.expression;
      if (e?.type === "CallExpression") return true;          // top-level call / IIFE
      if (e?.type === "AssignmentExpression") return true;
    }
  }
  return false;
}

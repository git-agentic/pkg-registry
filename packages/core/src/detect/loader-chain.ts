import * as acorn from "acorn";
import { base as walkBase } from "acorn-walk";
import { lineLocator } from "../rules/util.js";

export interface LoaderPrimitive {
  stage: "read" | "decode" | "write" | "launch";
  line: number;
  snippet: string;
  /** For read-stage primitives: the statically-known relative path/basename the read
   *  resolves to (e.g. `path.join(__dirname,'intro.js')` -> "intro.js"). Undefined
   *  when the read target isn't a static string (Spec6 — links the content-mismatch
   *  booster to the loader's ACTUAL read target, not any mismatch in the package). */
  readTarget?: string;
}
export interface LoaderBoosters { tempOrHidden: boolean; chmod: boolean; detached: boolean; unref: boolean; moduleLoad: boolean }
export interface LoaderAnalysis { primitives: LoaderPrimitive[]; correlated: boolean; boosters: LoaderBoosters; parseFailed: boolean;
  /** Stack overflow while parsing or walking (hostile nesting), not a syntax error: the caller must not downgrade a regex chain hit. */
  walkOverflow?: boolean;
  /** The walk hit its node or scope bound: unreachable for real input, so it is a safety stop, not a stack overflow. The
   *  caller uses the STRICT fallback (like a parse failure), never the loose overflow one. */
  walkTruncated?: boolean }

/** Bounded, deterministic taint tags a variable can carry. */
type Tag = "read" | "decoded" | "written-path";
type Category = "read" | "decode" | "write" | "launch" | "chmod";

// Node API surface we recognize, keyed by module → category → function names.
// A call is a primitive ONLY when its callee resolves (via binding tracking) to
// one of these module functions — an arbitrary `obj.readFileSync()` is not.
const MODULE_FNS: Record<string, Partial<Record<Category, Set<string>>>> = {
  fs: {
    read: new Set(["readFile", "readFileSync", "createReadStream"]),
    write: new Set(["writeFile", "writeFileSync", "createWriteStream", "cp", "cpSync", "copyFile", "copyFileSync"]),
    chmod: new Set(["chmod", "chmodSync"]),
  },
  zlib: {
    decode: new Set(["gunzip", "gunzipSync", "inflate", "inflateSync", "inflateRaw", "inflateRawSync", "brotliDecompress", "brotliDecompressSync", "unzip", "unzipSync"]),
  },
  child_process: {
    launch: new Set(["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync"]),
  },
};
// path functions used for package-relative-origin detection (not a primitive category).
const PATH_JOINERS = new Set(["join", "resolve"]);
// Buffer method pass-throughs that preserve payload taint.
const PASSTHROUGH_METHODS = new Set(["subarray", "slice", "toString", "valueOf", "at"]);
const JS_EXTS = new Set(["js", "cjs", "mjs", "json"]);

/** A resolved local binding: a namespace (whole module) or a specific module function. */
type Binding =
  | { kind: "namespace"; module: string }
  | { kind: "fn"; module: string; fn: string };

function propName(m: any): string | null {
  if (m.computed) return m.property?.type === "Literal" ? String(m.property.value) : null;
  return m.property?.type === "Identifier" ? m.property.name : null;
}
/** Snippets keep the first 160 chars; never copy a whole (possibly huge, nested) node to build one. */
const SNIP_SOURCE_CAP = 4096;
function snip(src: string, node: any): string {
  const s = src.slice(node.start, Math.min(node.end, node.start + SNIP_SOURCE_CAP)).replace(/\s+/g, " ");
  return s.length > 160 ? s.slice(0, 159) + "…" : s;
}
function isScope(n: any): boolean {
  return n.type === "Program" || n.type === "FunctionDeclaration" || n.type === "FunctionExpression" || n.type === "ArrowFunctionExpression";
}

/**
 * Safety bounds of the walk. A retained file is at most 2 MiB and yields at most about one node per byte, so the node
 * bound is unreachable for real input. Each callback costs O(scope depth), so scopes nested deeper than the scope
 * bound are merged into the deepest tracked one (the walk goes on) rather than tracked.
 */
const MAX_WALK_NODES = 4_194_304;
const MAX_SCOPE_DEPTH = 1000;
class WalkBoundError extends Error {}

/** Hostile nesting defeated the parser or the walk: a RangeError, or acorn's own "Not enough stack space" SyntaxError. A genuine syntax error is neither. */
function isStackOverflow(e: unknown): boolean {
  return e instanceof RangeError || (e instanceof SyntaxError && e.message.startsWith("Not enough stack space"));
}

type Visitor = (node: any, st: any, ancestors: any[], scopeChain: any[]) => void;

/**
 * acorn-walk's `ancestor` without recursion: the same nodes, in the same order (a node's visitor runs after its
 * children), with the same ancestor list. acorn-walk's base visitors only call back for children, so each node's
 * children are collected first and then walked from an explicit stack. The visitor also receives the scope chain
 * (innermost → outermost), kept incrementally so a deep expression does not make every callback O(depth).
 * Deterministic bounds: MAX_WALK_NODES throws a WalkBoundError; past MAX_SCOPE_DEPTH scopes merge instead of aborting.
 */
export function walkAncestor(root: any, visitors: Record<string, Visitor>): void {
  const ancestors: any[] = [];
  const scopes: any[] = []; // outermost → innermost
  // A frame holds its node's child list and an index into it: only the active path is held, never every child at once.
  type Frame = { node: any; type: string; isNew: boolean; list: any[]; ov: string | (string | undefined)[] | undefined; next: number };
  const stack: Frame[] = [];
  let visited = 0;
  const enter = (node: any, override?: string): void => {
    const type = override || node.type;
    const isNew = node !== ancestors[ancestors.length - 1]; // an override re-enters the same node
    if (isNew) {
      if (++visited > MAX_WALK_NODES) throw new WalkBoundError("loader-chain: node bound exceeded");
      ancestors.push(node);
      // Past MAX_SCOPE_DEPTH a deeper function joins the deepest tracked scope (over-approximation: taint is never lost).
      if (isScope(node) && scopes.length < MAX_SCOPE_DEPTH) scopes.push(node);
    }
    const visit = (walkBase as Record<string, any>)[type];
    if (visit == null) throw new Error(`No walker function defined for node type ${type}`);
    // acorn-walk walks these lists in order: every statement of `body` ("Statement"), every non-hole array element.
    if (type === "Program" || type === "BlockStatement" || type === "StaticBlock") { stack.push({ node, type, isNew, list: node.body, ov: "Statement", next: 0 }); return; }
    if (type === "ArrayExpression" || type === "ArrayPattern") { stack.push({ node, type, isNew, list: node.elements, ov: type === "ArrayExpression" ? "Expression" : "Pattern", next: 0 }); return; }
    const list: any[] = [];
    const ov: (string | undefined)[] = [];
    visit(node, undefined, (child: any, _st: any, o?: string) => { list.push(child); ov.push(o); });
    stack.push({ node, type, isNew, list, ov, next: 0 });
  };
  enter(root);
  while (stack.length) {
    const f = stack[stack.length - 1]!;
    if (f.next < f.list.length) { const i = f.next++; if (f.list[i]) enter(f.list[i], typeof f.ov === "string" ? f.ov : f.ov?.[i]); continue; } // holes are skipped
    visitors[f.type]?.(f.node, ancestors, ancestors, scopes.slice().reverse());
    if (f.isNew) { ancestors.pop(); if (scopes[scopes.length - 1] === f.node) scopes.pop(); }
    stack.pop();
  }
}

/**
 * Analyze a JS source for a packaged-payload materialization chain. `correlated`
 * requires bounded, binding-tracked, lexically-scoped dataflow: a launched target
 * whose path is a tainted written output, where the written data carries decode/read
 * taint that ORIGINATES from a package-relative read. Parse failure (TS/JSX/other
 * non-JS) → parseFailed:true; the caller falls back to a regex signal capped below
 * critical. Pure + deterministic + bounded — never throws.
 */
export function analyzeLoaderChain(source: string, opts: { moduleLoadReachable?: boolean } = {}): LoaderAnalysis {
  let ast: any;
  try {
    ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "module", allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowHashBang: true });
  } catch (moduleError) {
    try {
      ast = acorn.parse(source, { ecmaVersion: "latest", sourceType: "script", allowReturnOutsideFunction: true, allowHashBang: true });
    } catch (e) {
      // Either attempt may have exhausted the stack (a module file with deep nesting then also fails the script retry on `export`).
      return { primitives: [], correlated: false, boosters: { tempOrHidden: false, chmod: false, detached: false, unref: false, moduleLoad: false }, parseFailed: true, walkOverflow: isStackOverflow(moduleError) || isStackOverflow(e) };
    }
  }

  const primitives: LoaderPrimitive[] = [];
  const boosters: LoaderBoosters = { tempOrHidden: false, chmod: false, detached: false, unref: false, moduleLoad: false };
  let correlated = false;

  // --- Binding tracking (S1). name → what Node module / function it refers to. ---
  const bindings = new Map<string, Binding>();
  // --- Lexical taint store (S2). scopeNode → (varName → Tag set). ---
  const taint = new Map<any, Map<string, Set<Tag>>>();
  // Declaration initializer per name (last writer wins) — resolves identifier path args.
  const declInit = new Map<string, any>();
  // Scopes in which a decode occurred (gate for written-path).
  const decodeScopes = new Set<any>();
  // Structurally-recorded written-path expressions (for inline-repeat launch matching).
  const writtenPaths = new Map<string, Set<any>>();   // structKey → scopes that wrote it

  const scopeTaint = (s: any): Map<string, Set<Tag>> => {
    let m = taint.get(s);
    if (!m) { m = new Map(); taint.set(s, m); }
    return m;
  };
  const lookupTaint = (chain: any[], name: string): Set<Tag> | undefined => {
    for (const s of chain) { const t = taint.get(s)?.get(name); if (t) return t; }
    return undefined;
  };
  const declaringScope = (chain: any[], name: string): any => {
    for (const s of chain) { if (taint.get(s)?.has(name)) return s; }
    return chain[0];
  };
  const lineAt = lineLocator(source);   // built once; a per-primitive rescan from 0 is quadratic
  const record = (stage: LoaderPrimitive["stage"], node: any, readTarget?: string) =>
    primitives.push({ stage, line: lineAt(node.start), snippet: snip(source, node), ...(readTarget ? { readTarget } : {}) });

  // ---------- module reference resolution ----------
  function stripNode(m: string): string { return m.startsWith("node:") ? m.slice(5) : m; }
  function requireModule(node: any): string | null {
    if (node?.type === "CallExpression" && node.callee?.type === "Identifier" && node.callee.name === "require"
      && node.arguments?.length === 1) {
      const a = node.arguments[0];
      if (a.type === "Literal" && typeof a.value === "string") return stripNode(a.value);
      // require(`fs`): a template literal with no expressions is a static string.
      if (a.type === "TemplateLiteral" && a.expressions.length === 0 && typeof a.quasis[0]?.value?.cooked === "string") {
        return stripNode(a.quasis[0].value.cooked);
      }
    }
    return null;
  }
  /** Resolve a MemberExpression to a {module, fn} if it names a module function. */
  function resolveMemberFn(node: any): { module: string; fn: string } | null {
    if (node?.type !== "MemberExpression") return null;
    const fn = propName(node);
    if (!fn) return null;
    const obj = node.object;
    if (obj.type === "Identifier") {
      const b = bindings.get(obj.name);
      if (b?.kind === "namespace") return { module: b.module, fn };
      return null;
    }
    // X.promises.fn where X is a namespace binding (zlib.promises.gunzip / fs.promises.readFile)
    if (obj.type === "MemberExpression" && propName(obj) === "promises" && obj.object.type === "Identifier") {
      const b = bindings.get(obj.object.name);
      if (b?.kind === "namespace") return { module: b.module, fn };
    }
    return null;
  }
  /** Resolve any callee to {module, fn}: namespace member or member-binding identifier. */
  function resolveCalleeFn(callee: any): { module: string; fn: string } | null {
    if (callee?.type === "MemberExpression") return resolveMemberFn(callee);
    if (callee?.type === "Identifier") {
      const b = bindings.get(callee.name);
      if (b?.kind === "fn") return { module: b.module, fn: b.fn };
    }
    return null;
  }
  function categoryOf(module: string, fn: string): Category | null {
    const table = MODULE_FNS[module];
    if (!table) return null;
    for (const cat of Object.keys(table) as Category[]) { if (table[cat]!.has(fn)) return cat; }
    return null;
  }
  /** Classify a CallExpression into a primitive category, or null. Binding-gated. */
  function classifyCall(call: any): Category | null {
    const callee = call.callee;
    // Buffer.from(<data>, 'base64') → decode
    if (callee?.type === "MemberExpression" && callee.object?.type === "Identifier" && callee.object.name === "Buffer" && propName(callee) === "from") {
      const enc = call.arguments?.[1];
      return enc?.type === "Literal" && typeof enc.value === "string" && /^base64(?:url)?$/i.test(enc.value) ? "decode" : null;
    }
    // atob(<data>) → decode (ambient global)
    if (callee?.type === "Identifier" && callee.name === "atob") return "decode";
    const r = resolveCalleeFn(callee);
    return r ? categoryOf(r.module, r.fn) : null;
  }
  function isPromisifyCallee(callee: any): boolean {
    if (callee?.type === "Identifier") { const b = bindings.get(callee.name); return callee.name === "promisify" || (b?.kind === "fn" && b.fn === "promisify"); }
    if (callee?.type === "MemberExpression") return propName(callee) === "promisify";
    return false;
  }

  // ---------- package-relative READ origin (Spec1, the keystone) ----------
  function resolvesToPathJoiner(callee: any): boolean {
    if (callee?.type === "MemberExpression") {
      const r = resolveMemberFn(callee);
      return !!r && r.module === "path" && PATH_JOINERS.has(r.fn);
    }
    if (callee?.type === "Identifier") { const b = bindings.get(callee.name); return b?.kind === "fn" && b.module === "path" && PATH_JOINERS.has(b.fn); }
    return false;
  }
  function isPackageRelative(node: any, depth = 0): boolean {
    if (!node || depth > 12) return false;
    if (node.type === "Identifier") {
      if (node.name === "__dirname" || node.name === "__filename") return true;
      const init = declInit.get(node.name);
      return init && init !== node ? isPackageRelative(init, depth + 1) : false;
    }
    if (node.type === "Literal" && typeof node.value === "string") {
      const v = node.value;
      if (v.includes("://")) return false;             // URL
      if (v.startsWith("/")) return false;             // POSIX absolute
      if (/^[A-Za-z]:[\\/]/.test(v)) return false;     // Windows absolute
      return true;                                      // relative literal ("./x", "x/y", "intro.js")
    }
    if (node.type === "CallExpression") {
      const c = node.callee;
      if (c?.type === "MemberExpression" && c.object?.type === "Identifier" && c.object.name === "require" && propName(c) === "resolve") return true;
      if (resolvesToPathJoiner(c)) return isPackageRelative(node.arguments?.[0], depth + 1);
      return false;
    }
    return false;
  }

  // ---------- static read-target resolution (Spec6: link booster to the ACTUAL read) ----------
  /** Join literal path.join/resolve arguments into a relative string, skipping the
   *  __dirname/__filename base segment. Returns null when any segment isn't a static
   *  string literal (the target is then simply unknown, not guessed). */
  function joinLiteralParts(argNodes: any[]): string | null {
    const parts: string[] = [];
    for (const a of argNodes) {
      if (a?.type === "Identifier" && (a.name === "__dirname" || a.name === "__filename")) continue;
      if (a?.type === "Literal" && typeof a.value === "string") { parts.push(a.value); continue; }
      return null;
    }
    return parts.length ? parts.join("/").replace(/^\.\//, "") : null;
  }
  /** Statically-known relative path/basename a read's path argument resolves to, or
   *  undefined when it isn't a static string (identifier through a literal init,
   *  a relative literal, `require.resolve(...)`, or `path.join/resolve(__dirname, ...literals)`). */
  function staticReadTarget(node: any, depth = 0): string | undefined {
    if (!node || depth > 12) return undefined;
    if (node.type === "Identifier") {
      const init = declInit.get(node.name);
      return init && init !== node ? staticReadTarget(init, depth + 1) : undefined;
    }
    if (node.type === "Literal" && typeof node.value === "string") {
      const v = node.value;
      if (v.includes("://") || v.startsWith("/") || /^[A-Za-z]:[\\/]/.test(v)) return undefined;
      return v.replace(/^\.\//, "");
    }
    if (node.type === "CallExpression") {
      const c = node.callee;
      if (c?.type === "MemberExpression" && c.object?.type === "Identifier" && c.object.name === "require" && propName(c) === "resolve") {
        const arg = node.arguments?.[0];
        return arg?.type === "Literal" && typeof arg.value === "string" ? arg.value.replace(/^\.\//, "") : undefined;
      }
      if (resolvesToPathJoiner(c)) return joinLiteralParts(node.arguments ?? []) ?? undefined;
    }
    return undefined;
  }

  // ---------- expression-level payload taint ----------
  /** Tags an arbitrary expression yields: "read" (package-relative read) / "decoded". */
  function payloadTags(node: any, chain: any[], depth = 0): Set<Tag> {
    const out = new Set<Tag>();
    if (!node || depth > 40) return out;
    switch (node.type) {
      case "Identifier": {
        const t = lookupTaint(chain, node.name);
        if (t) for (const tag of t) if (tag === "read" || tag === "decoded") out.add(tag);
        return out;
      }
      case "AwaitExpression":
        return payloadTags(node.argument, chain, depth + 1);
      case "ParenthesizedExpression":
        return payloadTags(node.expression, chain, depth + 1);
      case "CallExpression": {
        const cat = classifyCall(node);
        if (cat === "decode") {
          const inner = payloadTags(node.arguments?.[0], chain, depth + 1);
          if (inner.has("read") || inner.has("decoded")) out.add("decoded");
          return out;
        }
        if (cat === "read") {
          if (isPackageRelative(node.arguments?.[0])) out.add("read");
          return out;
        }
        if (node.callee?.type === "MemberExpression" && PASSTHROUGH_METHODS.has(propName(node.callee) ?? "")) {
          return payloadTags(node.callee.object, chain, depth + 1);   // x.subarray(5), buf.toString()
        }
        return out;
      }
      case "MemberExpression":
        if (PASSTHROUGH_METHODS.has(propName(node) ?? "")) return payloadTags(node.object, chain, depth + 1);
        return out;
      default:
        return out;
    }
  }
  const carriesPayload = (tags: Set<Tag>): boolean => tags.has("read") || tags.has("decoded");

  // ---------- structural expression equality (S3, bounded) ----------
  /**
   * Canonical string of an expression's shape: two expressions have the same key
   * iff they are structurally equal (node types, names, literal values, member /
   * call / template shape) within the depth bound. `null` means never equal to
   * anything (unsupported node, regex literal, deeper than 20). Indexing writes
   * by this key makes each launch lookup O(1) instead of a scan of every write.
   */
  function structKey(n: any, depth = 0): string | null {
    if (!n || depth > 20) return null;
    switch (n.type) {
      case "Identifier": return `I${JSON.stringify(n.name)}`;
      case "Literal": {
        const v = n.value;
        if (v !== null && typeof v === "object") return null;   // RegExp: === never equal
        return `L${typeof v}${JSON.stringify(String(v))}`;
      }
      case "MemberExpression": {
        const o = structKey(n.object, depth + 1);
        const p = n.computed ? structKey(n.property, depth + 1) : `N${JSON.stringify(String(n.property?.name))}`;
        return o === null || p === null ? null : `M${n.computed ? 1 : 0}(${o},${p})`;
      }
      case "CallExpression": {
        const parts = [structKey(n.callee, depth + 1), ...(n.arguments ?? []).map((x: any) => structKey(x, depth + 1))];
        return parts.includes(null) ? null : `C(${parts.join(",")})`;
      }
      case "TemplateLiteral": {
        const q = (n.quasis ?? []).map((x: any) => JSON.stringify(x.value?.cooked ?? null));
        const e = (n.expressions ?? []).map((x: any) => structKey(x, depth + 1));
        return e.includes(null) ? null : `T(${q.join(",")};${e.join(",")})`;
      }
      default: return null;
    }
  }
  /** Is `target` a written-path? Identifier via scoped taint, or structural match to a visible recorded path. */
  function targetIsWrittenPath(target: any, chain: any[]): boolean {
    if (!target) return false;
    if (target.type === "Identifier" && lookupTaint(chain, target.name)?.has("written-path")) return true;
    const key = structKey(target);
    const scopes = key === null ? undefined : writtenPaths.get(key);
    return !!scopes && chain.some((s) => scopes.has(s));   // visibility: the write scope must enclose the launch
  }

  // ---------- temp/hidden booster ----------
  function isTempOrHidden(node: any): boolean {
    const resolved = node?.type === "Identifier" ? (declInit.get(node.name) ?? node) : node;
    if (!resolved) return false;
    const txt = source.slice(resolved.start, Math.min(resolved.end, resolved.start + SNIP_SOURCE_CAP));
    return /tmpdir\s*\(\s*\)|['"`]\/tmp\b|['"`]\.[A-Za-z0-9_]/.test(txt) || /\.tmpdir/.test(txt);
  }

  // ---------- collect require/import bindings from a declarator ----------
  function bindFromInit(id: any, init: any): void {
    if (!init) return;
    const mod = requireModule(init);
    if (mod && id.type === "Identifier") { bindings.set(id.name, { kind: "namespace", module: mod }); return; }
    if (mod && id.type === "ObjectPattern") {
      for (const p of id.properties ?? []) {
        if (p.type !== "Property" || p.value?.type !== "Identifier") continue;
        const fn = p.key?.type === "Identifier" ? p.key.name : (p.key?.type === "Literal" ? String(p.key.value) : null);
        if (fn) bindings.set(p.value.name, { kind: "fn", module: mod, fn });
      }
      return;
    }
    if (id.type !== "Identifier") return;
    const asMember = resolveMemberFn(init);           // fn alias: const g = zlib.gunzip
    if (asMember) { bindings.set(id.name, { kind: "fn", module: asMember.module, fn: asMember.fn }); return; }
    if (init.type === "CallExpression" && isPromisifyCallee(init.callee)) {   // const gunzip = promisify(zlib.gunzip)
      const inner = resolveMemberFn(init.arguments?.[0]) ?? resolveCalleeFn(init.arguments?.[0]);
      if (inner) bindings.set(id.name, { kind: "fn", module: inner.module, fn: inner.fn });
    }
  }

  // The walk is iterative, so a deep expression costs time, not a stack overflow. Exceeding the node or scope bound
  // (a RangeError) degrades to the parse-failure path, never throws out of the rule.
  try {
  walkAncestor(ast, {
    ImportDeclaration(node: any) {
      if (node.source?.type !== "Literal" || typeof node.source.value !== "string") return;
      const mod = stripNode(node.source.value);
      for (const spec of node.specifiers ?? []) {
        if (spec.type === "ImportDefaultSpecifier" || spec.type === "ImportNamespaceSpecifier") {
          bindings.set(spec.local.name, { kind: "namespace", module: mod });
        } else if (spec.type === "ImportSpecifier") {
          const fn = spec.imported?.type === "Identifier" ? spec.imported.name : String(spec.imported?.value);
          bindings.set(spec.local.name, { kind: "fn", module: mod, fn });
        }
      }
    },
    VariableDeclarator(node: any, _st: any, _ancestors: any[], chain: any[]) {
      if (!node.init) { if (node.id?.type === "Identifier") declInit.delete(node.id.name); return; }
      bindFromInit(node.id, node.init);
      if (node.id?.type !== "Identifier") return;
      const name = node.id.name;
      declInit.set(name, node.init);
      const relevant = new Set<Tag>([...payloadTags(node.init, chain)].filter((t) => t === "read" || t === "decoded"));
      scopeTaint(chain[0]).set(name, relevant);   // declaration REPLACES
    },
    AssignmentExpression(node: any, _st: any, _ancestors: any[], chain: any[]) {
      if (node.operator !== "=" || node.left.type !== "Identifier") return;
      const name = node.left.name;
      declInit.set(name, node.right);
      const relevant = new Set<Tag>([...payloadTags(node.right, chain)].filter((t) => t === "read" || t === "decoded"));
      scopeTaint(declaringScope(chain, name)).set(name, relevant);   // reassignment REPLACES (kill-on-reassign, S2)
    },
    CallExpression(node: any, _st: any, _ancestors: any[], chain: any[]) {
      const cat = classifyCall(node);
      const args = node.arguments ?? [];

      if (cat === "read") {
        record("read", node, staticReadTarget(args[0]));   // evidence for ANY recognized read
      } else if (cat === "decode") {
        // A decode only counts (primitive + scope gate) when it decodes payload
        // data — i.e. its input carries read/decoded taint. `Buffer.from(literal,
        // 'base64')` / `gunzipSync(nonPayload)` is not a materialization step and
        // must not seed the write-path gate (Spec2: DECODE += Buffer.from(<tainted>)).
        if (carriesPayload(payloadTags(args[0], chain))) {
          record("decode", node);
          decodeScopes.add(chain[0]);
        }
      } else if (cat === "write") {
        record("write", node);
        const [pathArg, dataArg] = args;
        const decodeInScope = chain.some((s) => decodeScopes.has(s));
        if (pathArg && decodeInScope && carriesPayload(payloadTags(dataArg, chain))) {
          if (pathArg.type === "Identifier") {
            const s = declaringScope(chain, pathArg.name);
            (scopeTaint(s).get(pathArg.name) ?? scopeTaint(s).set(pathArg.name, new Set()).get(pathArg.name)!).add("written-path");
          } else {
            const key = structKey(pathArg);
            if (key !== null) (writtenPaths.get(key) ?? writtenPaths.set(key, new Set()).get(key)!).add(chain[0]);
          }
        }
        if (pathArg && isTempOrHidden(pathArg)) boosters.tempOrHidden = true;
      } else if (cat === "chmod") {
        boosters.chmod = true;
      } else if (cat === "launch") {
        record("launch", node);
        if (targetIsWrittenPath(args[0], chain)) correlated = true;
        const optsArg = args.find((a: any) => a?.type === "ObjectExpression");
        if (optsArg) {
          for (const prop of optsArg.properties ?? []) {
            const key = prop.key?.name ?? prop.key?.value;
            if (key === "detached" && prop.value?.value === true) boosters.detached = true;
            if (key === "stdio" && prop.value?.value === "ignore") boosters.detached = true;
          }
        }
        return;
      }

      // process.dlopen(module, path) — LAUNCH when path is a written output.
      if (node.callee?.type === "MemberExpression" && node.callee.object?.type === "Identifier"
        && node.callee.object.name === "process" && propName(node.callee) === "dlopen") {
        record("launch", node);
        if (targetIsWrittenPath(args[1], chain)) correlated = true;
        return;
      }

      // require(...) as a native loader.
      if (node.callee?.type === "Identifier" && node.callee.name === "require") {
        const spec = args[0];
        if (spec && targetIsWrittenPath(spec, chain)) {           // require(<writtenPath>)
          record("launch", node);
          correlated = true;
        } else if (spec?.type === "Literal" && typeof spec.value === "string" && isPackageRelative(spec)) {
          const ext = spec.value.includes(".") ? spec.value.split(".").pop()! : "";
          if (ext && !JS_EXTS.has(ext.toLowerCase())) {           // require('./x.node') — non-JS packaged asset
            record("read", node, spec.value.replace(/^\.\//, ""));
            record("launch", node);
          }
        }
        return;
      }

      // unref booster: any `x.unref()`
      if (node.callee?.type === "MemberExpression" && propName(node.callee) === "unref") boosters.unref = true;
    },
  });
  boosters.moduleLoad = Boolean(opts.moduleLoadReachable) && topLevelExecution(ast);
  } catch (e) {
    const truncated = e instanceof WalkBoundError;
    return { primitives: [], correlated: false, boosters: { tempOrHidden: false, chmod: false, detached: false, unref: false, moduleLoad: false }, parseFailed: true,
      walkOverflow: !truncated && isStackOverflow(e), ...(truncated ? { walkTruncated: true } : {}) };
  }

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

import { parse as parseYaml } from "yaml";

export interface Coordinate {
  name: string;
  version: string;
  integrity?: string;
  /**
   * The raw `resolved` spec, set ONLY when the lockfile entry does not come from
   * a registry tarball (git, github shorthand, off-shape tarball URL, ...). The
   * proxy cannot audit such a source, so `audit-tree` blocks it (F19).
   */
  nonRegistry?: string;
}

interface LockPackageEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  link?: boolean;
  dev?: boolean;
}

/** True when `integrity` carries at least one pin in an algorithm the proxy can recompute. */
function hasKnownPin(integrity: string | undefined): boolean {
  return typeof integrity === "string" && integrity.split(/\s+/).some((t) => /^(?:sha1|sha256|sha512)-\S/.test(t));
}

/**
 * True when `resolved` has the shape of an http(s) registry tarball: the path
 * contains `/-/` and ends in `.tgz` (npm, yarn, pnpm, GitLab's `/-/@scope/n-1.0.0.tgz`).
 * Shape alone proves nothing about the host, so a registry coordinate also needs
 * an integrity pin (see `isRegistrySource`); the proxy then checks the pin against
 * the bytes it audited. shortcut: the file name is not bound to name-version
 * (hand-written test lockfiles use `x.tgz`).
 */
function isRegistryTarball(resolved: string): boolean {
  try {
    const u = new URL(resolved);
    return (u.protocol === "http:" || u.protocol === "https:") && u.pathname.includes("/-/") && u.pathname.endsWith(".tgz");
  } catch {
    return false;
  }
}

/** A registry source: registry-shaped URL AND a known-algorithm pin. Otherwise npm fetches unverified bytes. */
function isRegistrySource(resolved: string, integrity: string | undefined): boolean {
  return isRegistryTarball(resolved) && hasKnownPin(integrity);
}

const NAME_RE = /^(?:@[A-Za-z0-9~._-]+\/)?[A-Za-z0-9~._-]+$/;
const VERSION_RE = /^[^\s/:@?#]+$/;

/**
 * Lockfile text must not become coordinate text: a name outside the npm grammar becomes
 * `<unparsed>` and a version that is not a plain version string becomes `0.0.0`, and the entry is
 * flagged non-registry. (URLs, userinfo and signed query strings then cannot reach audit-tree output.)
 */
function sanitize(coord: Coordinate): Coordinate {
  const goodName = coord.name.length <= 214 && NAME_RE.test(coord.name);
  const goodVersion = VERSION_RE.test(coord.version);
  if (goodName && goodVersion) return coord;
  return {
    ...coord,
    name: goodName ? coord.name : "<unparsed>",
    version: goodVersion ? coord.version : "0.0.0",
    nonRegistry: coord.nonRegistry ?? "unparsed lockfile entry",
  };
}

/**
 * Dedupe on name@version. `nonRegistry` is sticky so a git row is never hidden by a registry twin, and
 * so is the integrity pin (a later duplicate without one must not erase it). Two entries with different
 * pins conflict: npm would install one of them, so the coordinate cannot be verified against one hash.
 */
function putCoord(byKey: Map<string, Coordinate>, raw: Coordinate): void {
  const coord = sanitize(raw);
  const key = `${coord.name}@${coord.version}`;
  const prev = byKey.get(key);
  if (prev?.nonRegistry !== undefined && coord.nonRegistry === undefined) coord.nonRegistry = prev.nonRegistry;
  if (prev?.integrity && !coord.integrity) coord.integrity = prev.integrity;
  else if (prev?.integrity && coord.integrity && prev.integrity !== coord.integrity && coord.nonRegistry === undefined) {
    coord.nonRegistry = "conflicting integrity pins for the same name@version";
  }
  byKey.set(key, coord);
}

/**
 * Parse an npm `package-lock.json` (v2/v3) into deduped, `name@version`-sorted
 * registry coordinates. Lockfile-format knowledge lives here, not on the proxy.
 * Skips the root ("") entry, workspace source entries (paths outside
 * node_modules/), `link:`/`file:` entries, and (when `omitDev`) dev deps.
 */
export function parseLockfile(raw: string, opts: { omitDev?: boolean } = {}): Coordinate[] {
  const doc = JSON.parse(raw) as { packages?: Record<string, LockPackageEntry> };
  const packages = doc.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error("unsupported lockfile: expected a v2/v3 'packages' map (run `npm install` to regenerate)");
  }
  const byKey = new Map<string, Coordinate>();
  for (const [path, entry] of Object.entries(packages)) {
    if (path === "" || !entry || entry.link) continue;
    // Workspace source entries live at their project path ("packages/api"), not
    // under node_modules/ — they are local projects, not registry coordinates.
    if (!path.includes("node_modules/")) continue;
    const resolved = entry.resolved ?? "";
    if (resolved.startsWith("file:") || resolved.startsWith("link:")) continue;
    if (opts.omitDev && entry.dev) continue;
    const name = entry.name ?? nameFromPath(path);
    if (!name || !entry.version) continue;
    const coord: Coordinate = { name, version: entry.version };
    if (entry.integrity) coord.integrity = entry.integrity;
    if (resolved && !isRegistrySource(resolved, entry.integrity)) coord.nonRegistry = resolved;
    putCoord(byKey, coord);
  }
  return [...byKey.values()].sort((a, b) => {
    const ka = `${a.name}@${a.version}`, kb = `${b.name}@${b.version}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

/** `node_modules/foo` -> `foo`; `node_modules/@scope/bar` -> `@scope/bar`. */
function nameFromPath(path: string): string {
  const marker = "node_modules/";
  const idx = path.lastIndexOf(marker);
  return idx >= 0 ? path.slice(idx + marker.length) : path;
}

/** yarn v1 header key `name@range` → name (strip the range after the last `@`, scope-aware). */
function yarnV1Name(spec: string): string {
  const s = spec.replace(/^"|"$/g, "").trim();
  const at = s.lastIndexOf("@");
  return at > 0 ? s.slice(0, at) : s;
}

function parseYarnV1(raw: string): Coordinate[] {
  const lines = raw.split(/\r?\n/);
  const byKey = new Map<string, Coordinate>();
  let headerName: string | null = null;
  let version: string | null = null;
  let integrity: string | undefined;
  let resolved: string | undefined;
  const flush = () => {
    if (headerName && version) {
      const coord: Coordinate = { name: headerName, version };
      // A `#<40-hex>` fragment on `resolved` is yarn v1's sha1 pin; carry it as an SRI so the proxy verifies it.
      const frag = resolved ? /#([0-9a-f]{40})$/i.exec(resolved)?.[1] : undefined;
      const pin = integrity ?? (frag ? "sha1-" + Buffer.from(frag, "hex").toString("base64") : undefined);
      if (pin) coord.integrity = pin;
      if (resolved && !resolved.startsWith("file:") && !resolved.startsWith("link:") && !isRegistrySource(resolved, pin)) coord.nonRegistry = resolved;
      putCoord(byKey, coord);
    }
    headerName = null; version = null; integrity = undefined; resolved = undefined;
  };
  for (const line of lines) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!/^\s/.test(line) && line.trimEnd().endsWith(":")) {
      flush();
      const firstSpec = line.trimEnd().replace(/:$/, "").split(",")[0]!.trim();
      headerName = yarnV1Name(firstSpec);
    } else {
      // `[^"\s]` (not `[^"]`) so the value class can't overlap the preceding `\s+`
      // — a version token has no whitespace, and the disjoint classes make this
      // linear-time on adversarial lockfile input (no polynomial backtracking).
      const v = line.trim().match(/^version\s+"?([^"\s]+)"?$/);
      if (v) version = v[1]!;
      const i = line.trim().match(/^integrity\s+(\S+)$/);
      if (i) integrity = i[1]!;
      const r = line.trim().match(/^resolved\s+"?([^"\s]+)"?$/);
      if (r) resolved = r[1]!;
    }
  }
  flush();
  return sortCoords([...byKey.values()]);
}

/** `name@protocol:range[, …]` → name: the leading (scoped) package name before its own `@`. */
function yarnBerryName(key: string): string {
  const s = key.replace(/^"|"$/g, "");
  return /^((?:@[^/@]+\/)?[^@/]+)@/.exec(s)?.[1] ?? "";
}

const BERRY_LOCAL_PROTOCOLS = new Set(["workspace", "patch", "link", "portal", "file", "exec"]);

function parseYarnBerry(raw: string): Coordinate[] {
  const doc = parseYaml(raw) as Record<string, { version?: string; resolution?: string }>;
  const byKey = new Map<string, Coordinate>();
  for (const [key, entry] of Object.entries(doc)) {
    if (key === "__metadata" || !entry || typeof entry !== "object") continue;
    const resolution = typeof entry.resolution === "string" ? entry.resolution : "";
    // Parse the locator structurally (`<name>@<protocol>:<rest>`); a substring test lets a
    // tarball URL containing "@npm:" or "@file:" pass as registry or local.
    const locator = /^((?:@[^/@]+\/)?[^@/]+)@([a-z]+):(.*)$/.exec(resolution);
    const protocol = locator?.[2];
    // Local sources and patch overlays (the patched `npm:` base is its own entry) are not registry coordinates.
    if (protocol && BERRY_LOCAL_PROTOCOLS.has(protocol)) continue;
    // The resolution names what yarn fetches (an alias key names something else).
    const name = locator?.[1] ?? (yarnBerryName(key) || key);
    const version = typeof entry.version === "string" && entry.version ? entry.version : "0.0.0";
    const coord: Coordinate = { name, version }; // berry checksum is not SRI → no integrity
    // Registry only when the resolved version is plain and is the version we audit.
    const registry = protocol === "npm" && /^[^\s#?/:@]+$/.test(locator![3]!) && locator![3] === entry.version;
    // Anything not provably a registry coordinate gates as non-registry; never skip it.
    if (!registry) coord.nonRegistry = resolution || key;
    putCoord(byKey, coord);
  }
  return sortCoords([...byKey.values()]);
}

/** Parse a yarn.lock (v1 text or berry YAML). `omitDev` is a no-op (yarn locks carry no dev flag). */
export function parseYarnLock(raw: string, _opts: { omitDev?: boolean } = {}): Coordinate[] {
  if (/__metadata:/.test(raw) && !/# yarn lockfile v1/.test(raw)) return parseYarnBerry(raw);
  return parseYarnV1(raw);
}

/** Strip a pnpm peer-dep suffix `(a@1)(b@2)` and a leading `/`. */
function pnpmStripKey(key: string): string {
  return key.replace(/\([^)]*\)/g, "").replace(/^\//, "");
}

/** Split a `name@version` (v6/v9) or `name/version` (v5) key into [name, version]. */
function pnpmNameVersion(key: string, slashStyle: boolean): [string, string] | null {
  const k = pnpmStripKey(key);
  if (slashStyle) {
    const at = k.lastIndexOf("/");
    if (at <= 0) return null;
    return [k.slice(0, at), k.slice(at + 1)];
  }
  const at = k.lastIndexOf("@");
  if (at <= 0) return null;
  return [k.slice(0, at), k.slice(at + 1)];
}

export function parsePnpmLock(raw: string, _opts: { omitDev?: boolean } = {}): Coordinate[] {
  const doc = parseYaml(raw) as { lockfileVersion?: string | number; packages?: Record<string, { version?: string; resolution?: { integrity?: string; tarball?: string; type?: string; repo?: string; commit?: string; directory?: string } }> };
  const packages = doc.packages;
  if (!packages || typeof packages !== "object") {
    throw new Error("unsupported pnpm lockfile: no 'packages' map");
  }
  const lv = String(doc.lockfileVersion ?? "");
  const slashStyle = lv.startsWith("5"); // v5 uses /name/version; v6+ uses name@version
  const byKey = new Map<string, Coordinate>();
  for (const [key, entry] of Object.entries(packages)) {
    if (key.startsWith("link:") || key.startsWith("file:")) continue;
    const nv = pnpmNameVersion(key, slashStyle);
    if (!nv) continue;
    const [name] = nv;
    let version = nv[1];
    if (!name || !version) continue;
    const res = entry?.resolution;
    if (res?.directory !== undefined || res?.type === "directory") continue;
    if (typeof res?.tarball === "string" && (res.tarball.startsWith("file:") || res.tarball.startsWith("link:"))) continue;
    // URL-keyed entries (`name@https://...`) carry the real version in the entry.
    if (/[:/]/.test(version) && typeof entry?.version === "string") version = entry.version;
    const coord: Coordinate = { name, version };
    const integrity = res?.integrity;
    if (integrity) coord.integrity = integrity;
    if (res?.type !== undefined && res.type !== "directory") coord.nonRegistry = `${res.type}:${res.repo ?? ""}#${res.commit ?? ""}`;
    else if (typeof res?.tarball === "string" && !isRegistrySource(res.tarball, integrity)) coord.nonRegistry = res.tarball;
    putCoord(byKey, coord);
  }
  return sortCoords([...byKey.values()]);
}

/** Detect the lockfile format (filename first, then content sniff) and parse. */
export function parseAnyLockfile(raw: string, opts: { filename?: string; omitDev?: boolean } = {}): Coordinate[] {
  const fn = (opts.filename ?? "").toLowerCase();
  if (fn.endsWith("package-lock.json") || fn.endsWith("npm-shrinkwrap.json")) return parseLockfile(raw, opts);
  if (fn.endsWith("yarn.lock")) return parseYarnLock(raw, opts);
  if (fn.endsWith("pnpm-lock.yaml")) return parsePnpmLock(raw, opts);
  // content sniff:
  const trimmed = raw.trimStart();
  if (trimmed.startsWith("{")) return parseLockfile(raw, opts);
  if (/# yarn lockfile v1/.test(raw) || (/__metadata:/.test(raw) && /resolution:/.test(raw) && /@npm:/.test(raw))) return parseYarnLock(raw, opts);
  if (/^lockfileVersion:/m.test(raw)) return parsePnpmLock(raw, opts);
  throw new Error("unrecognized lockfile format (expected package-lock.json, yarn.lock, or pnpm-lock.yaml)");
}

function sortCoords(coords: Coordinate[]): Coordinate[] {
  return coords.sort((a, b) => {
    const ka = `${a.name}@${a.version}`, kb = `${b.name}@${b.version}`;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

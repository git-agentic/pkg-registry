import { parse as parseYaml } from "yaml";

export interface Coordinate {
  name: string;
  version: string;
  integrity?: string;
}

interface LockPackageEntry {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  link?: boolean;
  dev?: boolean;
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
    byKey.set(`${name}@${entry.version}`, coord);
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
  const flush = () => {
    if (headerName && version) {
      const coord: Coordinate = { name: headerName, version };
      if (integrity) coord.integrity = integrity;
      byKey.set(`${headerName}@${version}`, coord);
    }
    headerName = null; version = null; integrity = undefined;
  };
  for (const line of lines) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!/^\s/.test(line) && line.trimEnd().endsWith(":")) {
      flush();
      const firstSpec = line.trimEnd().replace(/:$/, "").split(",")[0]!.trim();
      headerName = yarnV1Name(firstSpec);
    } else {
      const v = line.trim().match(/^version\s+"?([^"]+)"?$/);
      if (v) version = v[1]!;
      const i = line.trim().match(/^integrity\s+(\S+)$/);
      if (i) integrity = i[1]!;
    }
  }
  flush();
  return sortCoords([...byKey.values()]);
}

/** `name@npm:range` → name (everything before `@npm:`). */
function yarnBerryName(key: string): string {
  const s = key.replace(/^"|"$/g, "");
  const idx = s.indexOf("@npm:");
  return idx > 0 ? s.slice(0, idx) : s.replace(/@[^@]*$/, "");
}

function parseYarnBerry(raw: string): Coordinate[] {
  const doc = parseYaml(raw) as Record<string, { version?: string }>;
  const byKey = new Map<string, Coordinate>();
  for (const [key, entry] of Object.entries(doc)) {
    if (key === "__metadata" || !entry || typeof entry !== "object") continue;
    const name = yarnBerryName(key);
    const version = entry.version;
    if (!name || !version) continue;
    byKey.set(`${name}@${version}`, { name, version }); // berry checksum is not SRI → no integrity
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
  const doc = parseYaml(raw) as { lockfileVersion?: string | number; packages?: Record<string, { resolution?: { integrity?: string } }> };
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
    const [name, version] = nv;
    if (!name || !version) continue;
    const coord: Coordinate = { name, version };
    const integrity = entry?.resolution?.integrity;
    if (integrity) coord.integrity = integrity;
    byKey.set(`${name}@${version}`, coord);
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

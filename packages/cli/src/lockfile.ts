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
 * Skips the root ("") entry, `link:`/`file:` entries, and (when `omitDev`) dev deps.
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
    const resolved = entry.resolved ?? "";
    if (resolved.startsWith("file:") || resolved.startsWith("link:")) continue;
    if (opts.omitDev && entry.dev) continue;
    const name = entry.name ?? nameFromPath(path);
    if (!name || !entry.version) continue;
    const coord: Coordinate = { name, version: entry.version };
    if (entry.integrity) coord.integrity = entry.integrity;
    byKey.set(`${name}@${entry.version}`, coord);
  }
  return [...byKey.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

/** `node_modules/foo` -> `foo`; `node_modules/@scope/bar` -> `@scope/bar`. */
function nameFromPath(path: string): string {
  const marker = "node_modules/";
  const idx = path.lastIndexOf(marker);
  return idx >= 0 ? path.slice(idx + marker.length) : path;
}

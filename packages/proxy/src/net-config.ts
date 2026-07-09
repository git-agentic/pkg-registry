/**
 * Pure network-trust configuration helpers (Phase 23, ADR-0036).
 * Parsing + validation only — no I/O, no env access. `index.ts` owns the
 * fail-closed FATAL wrapping; `upstream.ts`/`server.ts` own enforcement.
 * All origin comparison goes through WHATWG `URL.origin` (normalizes case
 * and default ports) — never hand-rolled string matching.
 */

function toHttpUrl(raw: string, what: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${what} is not a valid URL: "${raw}"`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`${what} must be http(s), got "${url.protocol}" ("${raw}")`);
  }
  return url;
}

/**
 * Parse the comma-separated `SENTINEL_TARBALL_ORIGINS` allowlist. Each entry
 * must be a bare http(s) origin — no path, query, or fragment. Throws on any
 * invalid entry (the caller FATALs). Empty/blank input ⇒ [].
 */
export function parseTarballOrigins(raw: string): string[] {
  const origins: string[] = [];
  for (const entry of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    const url = toHttpUrl(entry, "SENTINEL_TARBALL_ORIGINS entry");
    if (url.pathname !== "/" || url.search || url.hash) {
      throw new Error(`SENTINEL_TARBALL_ORIGINS entry must be a bare origin (no path/query/hash): "${entry}"`);
    }
    origins.push(url.origin);
  }
  return origins;
}

/**
 * Validate `SENTINEL_PUBLIC_BASE_URL`: http(s), no query/fragment. A path
 * prefix IS allowed (proxy mounted behind a load-balancer route). Returns the
 * URL with any trailing slash stripped, ready for `${base}/pkg/-/file.tgz`.
 */
export function parsePublicBaseUrl(raw: string): string {
  const trimmed = raw.trim();
  const url = toHttpUrl(trimmed, "SENTINEL_PUBLIC_BASE_URL");
  if (url.search || url.hash) {
    throw new Error(`SENTINEL_PUBLIC_BASE_URL must not have a query or fragment: "${raw}"`);
  }
  return trimmed.replace(/\/+$/, "");
}

/**
 * True iff a Host header names loopback — `localhost`, `127.0.0.0/8`, or
 * `[::1]` — with any port. The safe zero-config dev case: only here may the
 * packument rewrite derive its base URL from the request (ADR-0036).
 */
export function isLoopbackHost(hostHeader: string): boolean {
  if (!hostHeader) return false;
  let hostname: string;
  try {
    hostname = new URL(`http://${hostHeader}`).hostname;
  } catch {
    return false;
  }
  return hostname === "localhost" || hostname === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

/**
 * Throw unless `url` is http(s) AND its origin is the configured registry
 * origin or in the extra allowlist. Called BEFORE any fetch — a disallowed
 * URL is never requested at all, so there is no DNS/IP surface (ADR-0036).
 */
export function assertAllowedTarballUrl(url: string, registryOrigin: string, extraOrigins: readonly string[]): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`malformed tarball URL "${url}"`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`tarball URL protocol "${parsed.protocol}" is not allowed ("${url}")`);
  }
  if (parsed.origin !== registryOrigin && !extraOrigins.includes(parsed.origin)) {
    throw new Error(`tarball origin ${parsed.origin} is not the registry origin ${registryOrigin} and not in SENTINEL_TARBALL_ORIGINS`);
  }
}

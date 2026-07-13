import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { RegistrySignature } from "@sentinel/core";
import { assertAllowedTarballUrl } from "./net-config.js";
import { readBodyCapped } from "./limits.js";

export interface UpstreamVersion {
  version: string;
  author: string | null;
  maintainers: string[];
  license: string | null;
  signatures: RegistrySignature[] | null;
  hasProvenance: boolean;
  integrity: string | null;
  hasInstallScripts: boolean;
}

export interface UpstreamPackument {
  /** npm-shaped packument document. The server rewrites each `dist.tarball`. */
  doc: PackumentDoc;
  /** Normalised per-version metadata used by the audit engine. */
  versions: Record<string, UpstreamVersion>;
  /** Per-version publish timestamps from the packument `time` object (Phase 16). */
  time?: Record<string, string>;
}

export interface PackumentDoc {
  name: string;
  "dist-tags"?: Record<string, string>;
  versions: Record<string, VersionManifest>;
  [k: string]: unknown;
}

interface VersionManifest {
  name: string;
  version: string;
  dist: { tarball: string; integrity?: string; signatures?: { keyid: string; sig: string }[]; attestations?: unknown };
  scripts?: Record<string, string>;
  author?: unknown;
  maintainers?: { name: string }[];
  license?: string;
  [k: string]: unknown;
}

export interface Upstream {
  readonly name: string;
  getPackument(pkg: string): Promise<UpstreamPackument>;
  getTarball(pkg: string, version: string): Promise<Buffer>;
  /** Fetch the attestation-endpoint response for a version; null when unavailable.
   *  Acquisition-path network (invariant #3 keeps the AUDIT offline, not this). */
  getAttestations(pkg: string, version: string): Promise<unknown | null>;
  /** Optional byte-preserving forwarding for the bounded Phase 33 compatibility surface. */
  proxyRegistryRequest?(pathAndQuery: string, init: { method: string; headers: Record<string, string>; body?: Buffer }): Promise<{
    status: number; headers: Record<string, string>; body: Buffer;
  }>;
}

function authorString(a: unknown): string | null {
  if (!a) return null;
  if (typeof a === "string") return a;
  if (typeof a === "object" && a && "name" in a) return String((a as { name: unknown }).name);
  return null;
}

function normalizeVersion(m: VersionManifest): UpstreamVersion {
  return {
    version: m.version,
    author: authorString(m.author),
    maintainers: (m.maintainers ?? []).map((x) => x.name).filter(Boolean),
    license: typeof m.license === "string" ? m.license : null,
    signatures: Array.isArray(m.dist?.signatures) && m.dist.signatures.length > 0 ? m.dist.signatures : null,
    hasProvenance: Boolean(m.dist?.attestations),
    integrity: m.dist?.integrity ?? null,
    hasInstallScripts: ["preinstall", "install", "postinstall"].some(
      (h) => Boolean(m.scripts?.[h]),
    ),
  };
}

/**
 * Hop cap for `fetchPinned` — bounds both the redirect chain length and any
 * pathological redirect loop (ADR-0036).
 */
const MAX_TARBALL_REDIRECTS = 5;

/** Fetches from the real npm registry. */
export class NpmUpstream implements Upstream {
  readonly name = "npm";
  /** Origin tarball URLs must match — a packument-controlled URL is never fetched cross-origin (ADR-0036). */
  private readonly registryOrigin: string;
  constructor(
    private readonly registry = "https://registry.npmjs.org",
    private readonly tarballOrigins: readonly string[] = [],
    private readonly maxTarballBytes = 256 * 1024 * 1024,
    private readonly maxPackumentBytes = 128 * 1024 * 1024,
  ) {
    this.registryOrigin = new URL(registry).origin;
  }

  /**
   * Fetch `initialUrl`, re-validating the origin allowlist on every hop
   * instead of letting `fetch` auto-follow redirects. undici's default
   * `redirect: "follow"` would revalidate only the initial URL and then
   * silently trust wherever a 3xx `Location` points — including an
   * internal/metadata address — which reopens the SSRF surface this
   * allowlist exists to close. `redirect: "manual"` plus a re-check per hop
   * keeps legitimate redirecting mirrors (Artifactory/Nexus/Verdaccio)
   * working while refusing to follow a hop off the allowlist (ADR-0036).
   */
  private async fetchPinned(initialUrl: string, what: string, init: RequestInit = {}): Promise<Response> {
    let url = initialUrl;
    for (let hop = 0; hop <= MAX_TARBALL_REDIRECTS; hop++) {
      try {
        assertAllowedTarballUrl(url, this.registryOrigin, this.tarballOrigins);
      } catch (err) {
        throw new HttpError(502, `refusing ${what}: ${(err as Error).message}`);
      }
      const res = await fetch(url, { ...init, redirect: "manual" });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        if (!loc) return res; // no Location — let the caller's !res.ok handle it
        url = new URL(loc, url).href;
        continue;
      }
      return res;
    }
    throw new HttpError(502, `refusing ${what}: too many redirects (> ${MAX_TARBALL_REDIRECTS})`);
  }

  async getPackument(pkg: string): Promise<UpstreamPackument> {
    const res = await this.fetchPinned(
      `${this.registry}/${encodeURIComponent(pkg).replaceAll("%40", "@")}`,
      `packument fetch for ${pkg}`,
    );
    if (!res.ok) throw new HttpError(res.status, `upstream packument ${pkg}: ${res.status}`);
    const body = await readBodyCapped(res, this.maxPackumentBytes, `packument ${pkg}`)
      .catch((err) => { throw new HttpError(502, `upstream packument ${pkg}: ${(err as Error).message}`); });
    const doc = JSON.parse(body.toString("utf8")) as PackumentDoc;
    const versions: Record<string, UpstreamVersion> = {};
    for (const [v, m] of Object.entries(doc.versions ?? {})) {
      versions[v] = normalizeVersion(m);
    }
    const time = (doc.time && typeof doc.time === "object")
      ? Object.fromEntries(Object.entries(doc.time as Record<string, unknown>).filter(([, v]) => typeof v === "string") as [string, string][])
      : undefined;
    return { doc, versions, time };
  }

  async getTarball(pkg: string, version: string): Promise<Buffer> {
    const pm = await this.getPackument(pkg);
    const url = pm.doc.versions[version]?.dist?.tarball;
    if (!url) throw new HttpError(404, `no tarball for ${pkg}@${version}`);
    const res = await this.fetchPinned(url, `tarball fetch for ${pkg}@${version}`);
    if (!res.ok) throw new HttpError(res.status, `upstream tarball ${pkg}@${version}: ${res.status}`);
    return readBodyCapped(res, this.maxTarballBytes, `tarball ${pkg}@${version}`)
      .catch((err) => { throw new HttpError(502, `upstream tarball ${pkg}@${version}: ${(err as Error).message}`); });
  }

  async getAttestations(pkg: string, version: string): Promise<unknown | null> {
    try {
      const name = encodeURIComponent(pkg).replaceAll("%40", "@");
      const res = await this.fetchPinned(
        `${this.registry}/-/npm/v1/attestations/${name}@${version}`,
        `attestations fetch for ${pkg}@${version}`,
      );
      if (!res.ok) return null;
      const body = await readBodyCapped(res, this.maxPackumentBytes, `attestations ${pkg}@${version}`);
      return JSON.parse(body.toString("utf8"));
    } catch {
      return null; // fail-open to "unknown" — an outage must not break installs
    }
  }

  async proxyRegistryRequest(pathAndQuery: string, init: { method: string; headers: Record<string, string>; body?: Buffer }) {
    const target = new URL(pathAndQuery, `${this.registry}/`);
    if (target.origin !== this.registryOrigin) throw new HttpError(502, "refusing compatibility proxy outside registry origin");
    return new Promise<{ status: number; headers: Record<string, string>; body: Buffer }>((resolve, reject) => {
      const request = (target.protocol === "https:" ? httpsRequest : httpRequest)(target, {
        method: init.method, headers: init.headers,
      }, (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > this.maxPackumentBytes) {
            response.destroy(new Error(`compatibility route ${target.pathname} exceeds ${this.maxPackumentBytes} bytes`));
            return;
          }
          chunks.push(Buffer.from(chunk));
        });
        response.on("error", (error) => reject(new HttpError(502, `upstream compatibility route: ${error.message}`)));
        response.on("end", () => {
          const headers: Record<string, string> = {};
          for (const [name, value] of Object.entries(response.headers)) {
            if (value !== undefined) headers[name] = Array.isArray(value) ? value.join(", ") : value;
          }
          resolve({ status: response.statusCode ?? 502, headers, body: Buffer.concat(chunks) });
        });
      });
      request.on("error", (error) => reject(new HttpError(502, `upstream compatibility route: ${error.message}`)));
      if (init.body) request.write(init.body);
      request.end();
    });
  }
}

interface RegistryDoc {
  packages: Record<
    string,
    {
      name: string;
      author: string | null;
      /** Per-version publish timestamps (Phase 16); absent on older fixture registries. */
      time?: Record<string, string>;
      versions: Record<
        string,
        {
          version: string;
          author: string | null;
          /** Per-version maintainer names (Phase 16); absent on older fixture registries. */
          maintainers?: string[];
          license: string | null;
          hasInstallScripts: boolean;
          signatures?: { keyid: string; sig: string }[] | null;
          attestations?: boolean;
          attestationsFile?: string | null;
          dist: { tarballFile: string; integrity: string; unpackedSize: number; fileCount: number };
        }
      >;
    }
  >;
}

/**
 * Serves the packed fixtures in `fixtures/` — hermetic, offline, deterministic.
 * Used by the test suite and the local demo so the malware-detection guarantee
 * never depends on a live network.
 */
export class LocalFixtureUpstream implements Upstream {
  readonly name = "local-fixtures";
  private readonly doc: RegistryDoc;
  constructor(private readonly fixturesDir: string) {
    this.doc = JSON.parse(readFileSync(join(fixturesDir, "registry.json"), "utf8")) as RegistryDoc;
  }

  async getPackument(pkg: string): Promise<UpstreamPackument> {
    const p = this.doc.packages[pkg];
    if (!p) throw new HttpError(404, `unknown fixture package ${pkg}`);
    const versions: Record<string, UpstreamVersion> = {};
    const docVersions: Record<string, VersionManifest> = {};
    const distTags: Record<string, string> = {};
    let latest = "0.0.0";
    for (const [v, m] of Object.entries(p.versions)) {
      versions[v] = {
        version: v,
        author: m.author,
        maintainers: m.maintainers ?? [],
        license: m.license,
        signatures: m.signatures ?? null,
        hasProvenance: Boolean(m.attestations),
        integrity: m.dist.integrity,
        hasInstallScripts: m.hasInstallScripts,
      };
      docVersions[v] = {
        name: pkg,
        version: v,
        dist: {
          tarball: `fixture:${pkg}@${v}`,
          integrity: m.dist.integrity,
          signatures: m.signatures ?? undefined,
          attestations: m.attestations ? {} : undefined,
        },
        license: m.license ?? undefined,
        // npm reads this flag from the packument to decide whether to run a package's install
        // scripts (an optimization that skips extraction otherwise). Without it, npm would never
        // run enforce-probe's postinstall on a by-name install.
        hasInstallScript: m.hasInstallScripts,
      };
      if (cmpSemver(v, latest) > 0) latest = v;
    }
    distTags.latest = latest;
    return { doc: { name: pkg, "dist-tags": distTags, versions: docVersions }, versions, time: p.time };
  }

  async getTarball(pkg: string, version: string): Promise<Buffer> {
    const m = this.doc.packages[pkg]?.versions[version];
    if (!m) throw new HttpError(404, `unknown fixture ${pkg}@${version}`);
    const buf = readFileSync(join(this.fixturesDir, ".tarballs", m.dist.tarballFile));
    const integrity = `sha512-${createHash("sha512").update(buf).digest("base64")}`;
    if (integrity !== m.dist.integrity) {
      throw new HttpError(502, `integrity mismatch for ${pkg}@${version}`);
    }
    return buf;
  }

  async getAttestations(pkg: string, version: string): Promise<unknown | null> {
    const m = this.doc.packages[pkg]?.versions[version];
    if (!m?.attestationsFile) return null;
    return JSON.parse(readFileSync(join(this.fixturesDir, "attestations", m.attestationsFile), "utf8"));
  }
}

/** Pick the immediate predecessor version (for diff-mode auditing). */
export function previousVersion(versions: string[], target: string): string | null {
  const lower = versions.filter((v) => cmpSemver(v, target) < 0).sort(cmpSemver);
  return lower.length ? (lower[lower.length - 1] ?? null) : null;
}

/** Minimal semver compare (major.minor.patch; prerelease tags compared lexically). */
export function cmpSemver(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  if (pa.pre === pb.pre) return 0;
  if (!pa.pre) return 1; // release > prerelease
  if (!pb.pre) return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

function parse(v: string): { nums: number[]; pre: string } {
  const [core = "", pre = ""] = v.replace(/^v/, "").split("-", 2);
  return { nums: core.split(".").map((n) => parseInt(n, 10) || 0), pre };
}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

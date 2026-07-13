import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import type { Audit } from "@sentinel/core";
import { cmpSemver } from "./upstream.js";

export interface StoredVersion {
  name: string;
  version: string;
  integrity: string;
  manifest: Record<string, unknown>;
  audit: Audit;
  actor: string;
  publishedAt: string;
}

export interface PrivatePackument {
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, Record<string, unknown>>;
}

interface Entry { meta: StoredVersion; tarball: Buffer; }

export class PublicationConflictError extends Error {}

/** Authoritative store for published private packages: tarball bytes + manifest + the
 * policy-independent Audit. Optional filesystem persistence (`<dir>/<enc>/<version>/`). */
export class PrivatePackageStore {
  private byName = new Map<string, Map<string, Entry>>();

  constructor(private readonly dir?: string) {
    if (dir && existsSync(dir)) this.load(dir);
  }

  has(name: string): boolean {
    return (this.byName.get(name)?.size ?? 0) > 0;
  }

  names(): string[] {
    return [...this.byName.keys()];
  }

  versions(name: string): string[] {
    return [...(this.byName.get(name)?.keys() ?? [])];
  }

  getVersion(name: string, version: string): StoredVersion | undefined {
    return this.byName.get(name)?.get(version)?.meta;
  }

  getTarball(name: string, version: string): Buffer | undefined {
    return this.byName.get(name)?.get(version)?.tarball;
  }

  getAudit(name: string, version: string): Audit | undefined {
    return this.byName.get(name)?.get(version)?.meta.audit;
  }

  publish(v: {
    name: string; version: string; integrity: string;
    manifest: Record<string, unknown>; tarball: Buffer; audit: Audit; actor: string;
  }): StoredVersion {
    if (this.getVersion(v.name, v.version) || (this.dir && existsSync(this.dirFor(v.name, v.version)))) {
      throw new PublicationConflictError(`version already published: ${v.name}@${v.version}`);
    }
    const meta: StoredVersion = {
      name: v.name, version: v.version, integrity: v.integrity,
      manifest: v.manifest, audit: v.audit, actor: v.actor,
      publishedAt: new Date().toISOString(),
    };
    this.persistAtomic(meta, v.tarball);
    // Memory visibility is the commit point for in-memory stores and follows the
    // atomic directory rename for persistent stores. No caller can see half a version.
    let versions = this.byName.get(v.name);
    if (!versions) { versions = new Map(); this.byName.set(v.name, versions); }
    versions.set(v.version, { meta, tarball: Buffer.from(v.tarball) });
    return meta;
  }

  /** Backwards-compatible seed helper; production publish uses the same atomic primitive. */
  put(v: {
    name: string; version: string; integrity: string;
    manifest: Record<string, unknown>; tarball: Buffer; audit: Audit; actor: string;
  }): StoredVersion {
    return this.publish(v);
  }

  packument(name: string): PrivatePackument | undefined {
    const versions = this.byName.get(name);
    if (!versions || versions.size === 0) return undefined;
    const versionDocs: Record<string, Record<string, unknown>> = {};
    let latest = "0.0.0";
    for (const [v, entry] of versions) {
      versionDocs[v] = structuredClone(entry.meta.manifest);
      if (cmpSemver(v, latest) > 0) latest = v;
    }
    return { name, "dist-tags": { latest }, versions: versionDocs };
  }

  // ---- persistence (best-effort, mirrors AuditStore's style) ----

  private dirFor(name: string, version: string): string {
    return join(this.dir!, encodeURIComponent(name), encodeURIComponent(version));
  }

  private persistAtomic(meta: StoredVersion, tarball: Buffer): void {
    if (!this.dir) return;
    const packageDir = join(this.dir, encodeURIComponent(meta.name));
    const finalDir = this.dirFor(meta.name, meta.version);
    let staging: string | undefined;
    try {
      mkdirSync(packageDir, { recursive: true });
      staging = mkdtempSync(join(packageDir, ".publish-"));
      writeFileSync(join(staging, "package.tgz"), tarball, { flag: "wx" });
      const { ...metaJson } = meta;
      writeFileSync(join(staging, "meta.json"), JSON.stringify(metaJson, null, 2), { flag: "wx" });
      renameSync(staging, finalDir);
      staging = undefined;
    } finally {
      if (staging) rmSync(staging, { recursive: true, force: true });
    }
  }

  private load(dir: string): void {
    for (const enc of readdirSync(dir)) {
      const name = decodeURIComponent(enc);
      const pkgDir = join(dir, enc);
      let versionDirs: string[];
      try { versionDirs = readdirSync(pkgDir); } catch { continue; }
      for (const encVersion of versionDirs) {
        try {
          const version = decodeURIComponent(encVersion);
          const meta = JSON.parse(readFileSync(join(pkgDir, encVersion, "meta.json"), "utf8")) as StoredVersion;
          const tarball = readFileSync(join(pkgDir, encVersion, "package.tgz"));
          let versions = this.byName.get(name);
          if (!versions) { versions = new Map(); this.byName.set(name, versions); }
          versions.set(version, { meta, tarball });
        } catch {
          /* skip a corrupt entry */
        }
      }
    }
  }
}

import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { Buffer } from "node:buffer";
import type { Audit, RetractionAdvisory, RetractionReason, VerifiedClaim } from "@sentinel/core";
import { cmpSemver } from "./upstream.js";

export interface StoredVersion {
  name: string;
  version: string;
  integrity: string;
  manifest: Record<string, unknown>;
  audit: Audit;
  actor: string;
  publishedAt: string;
  /** Immutable ownership attribution captured when this version was accepted. */
  claimAtPublication?: Pick<VerifiedClaim, "namespace" | "domain" | "claimantPublicKey">;
  /** Original publish attestation document retained as immutable publication history. */
  attestations?: unknown;
}

export interface PrivatePackument {
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, Record<string, unknown>>;
  _sentinel?: { retractions: Record<string, RetractionTombstone> };
}

export type { RetractionAdvisory, RetractionReason } from "@sentinel/core";

export interface RetractionTombstone {
  retractedAt: string;
  reason: RetractionReason;
  advisoryId: string;
}

interface OperationalState {
  schema: 1;
  retractions: { name: string; version: string; tombstone: RetractionTombstone }[];
  downloads: { name: string; version: string; count: number }[];
  windowHits: { age: number; downloads: number; both: number };
}

interface Entry { meta: StoredVersion; tarball: Buffer; }

export class PublicationConflictError extends Error {}

/** Authoritative store for published private packages: tarball bytes + manifest + the
 * policy-independent Audit. Optional filesystem persistence (`<dir>/<enc>/<version>/`). */
export class PrivatePackageStore {
  private byName = new Map<string, Map<string, Entry>>();
  private retractions = new Map<string, RetractionTombstone>();
  private downloads = new Map<string, number>();
  private windowHits = { age: 0, downloads: 0, both: 0 };

  constructor(private readonly dir?: string, private readonly now: () => number = Date.now) {
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

  getAttestations(name: string, version: string): unknown | undefined {
    const value = this.byName.get(name)?.get(version)?.meta.attestations;
    return value === undefined ? undefined : structuredClone(value);
  }

  getRetraction(name: string, version: string): RetractionTombstone | undefined {
    const found = this.retractions.get(this.key(name, version));
    return found ? structuredClone(found) : undefined;
  }

  getRetractionAdvisory(name: string, version: string): RetractionAdvisory | undefined {
    const entry = this.byName.get(name)?.get(version);
    const tombstone = this.retractions.get(this.key(name, version));
    if (!entry || !tombstone) return undefined;
    return {
      kind: "retraction", id: tombstone.advisoryId, name, version, integrity: entry.meta.integrity,
      retractedAt: tombstone.retractedAt, reason: tombstone.reason,
      severity: tombstone.reason === "security" ? "high" : "medium",
    };
  }

  retractionAdvisories(): RetractionAdvisory[] {
    const advisories: RetractionAdvisory[] = [];
    for (const [name, versions] of this.byName) {
      for (const version of versions.keys()) {
        const advisory = this.getRetractionAdvisory(name, version);
        if (advisory) advisories.push(advisory);
      }
    }
    return advisories;
  }

  publish(v: {
    name: string; version: string; integrity: string;
    manifest: Record<string, unknown>; tarball: Buffer; audit: Audit; actor: string;
    claimAtPublication?: Pick<VerifiedClaim, "namespace" | "domain" | "claimantPublicKey">;
    attestations?: unknown;
  }): StoredVersion {
    if (this.getRetraction(v.name, v.version)) {
      throw new PublicationConflictError(`version identifier is permanently spent by retraction: ${v.name}@${v.version}`);
    }
    if (this.getVersion(v.name, v.version) || (this.dir && existsSync(this.dirFor(v.name, v.version)))) {
      throw new PublicationConflictError(`version already published: ${v.name}@${v.version}`);
    }
    const meta: StoredVersion = {
      name: v.name, version: v.version, integrity: v.integrity,
      manifest: v.manifest, audit: v.audit, actor: v.actor,
      publishedAt: new Date(this.now()).toISOString(),
      ...(v.claimAtPublication ? { claimAtPublication: structuredClone(v.claimAtPublication) } : {}),
      ...(v.attestations !== undefined ? { attestations: structuredClone(v.attestations) } : {}),
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
    claimAtPublication?: Pick<VerifiedClaim, "namespace" | "domain" | "claimantPublicKey">;
    attestations?: unknown;
  }): StoredVersion {
    return this.publish(v);
  }

  retract(input: { name: string; version: string; reason: RetractionReason; retractedAt: string; advisoryId: string }): RetractionTombstone {
    if (!this.getVersion(input.name, input.version)) throw new Error(`unknown native version ${input.name}@${input.version}`);
    if (this.getRetraction(input.name, input.version)) throw new PublicationConflictError(`version already retracted: ${input.name}@${input.version}`);
    const tombstone: RetractionTombstone = {
      retractedAt: input.retractedAt,
      reason: input.reason,
      advisoryId: input.advisoryId,
    };
    const next = new Map(this.retractions);
    next.set(this.key(input.name, input.version), tombstone);
    this.persistOperationalState(next, this.downloads, this.windowHits);
    this.retractions = next;
    return structuredClone(tombstone);
  }

  recordDownload(name: string, version: string): number {
    if (!this.getVersion(name, version)) throw new Error(`unknown native version ${name}@${version}`);
    const key = this.key(name, version);
    const next = new Map(this.downloads);
    next.set(key, (next.get(key) ?? 0) + 1);
    this.persistOperationalState(this.retractions, next, this.windowHits);
    this.downloads = next;
    return next.get(key)!;
  }

  downloadCount(name: string, version: string): number {
    return this.downloads.get(this.key(name, version)) ?? 0;
  }

  recordRetractionWindowHit(hit: { ageExceeded: boolean; downloadsExceeded: boolean }): void {
    const next = { ...this.windowHits };
    if (hit.ageExceeded && hit.downloadsExceeded) next.both++;
    else if (hit.ageExceeded) next.age++;
    else if (hit.downloadsExceeded) next.downloads++;
    else return;
    this.persistOperationalState(this.retractions, this.downloads, next);
    this.windowHits = next;
  }

  retractionWindowHits(): { age: number; downloads: number; both: number } {
    return { ...this.windowHits };
  }

  packument(name: string): PrivatePackument | undefined {
    const versions = this.byName.get(name);
    if (!versions || versions.size === 0) return undefined;
    const versionDocs: Record<string, Record<string, unknown>> = {};
    let latest = "0.0.0";
    const retractions: Record<string, RetractionTombstone> = {};
    for (const [v, entry] of versions) {
      const tombstone = this.retractions.get(this.key(name, v));
      if (tombstone) {
        retractions[v] = structuredClone(tombstone);
        continue;
      }
      versionDocs[v] = structuredClone(entry.meta.manifest);
      if (cmpSemver(v, latest) > 0) latest = v;
    }
    const active = Object.keys(versionDocs).length > 0;
    return {
      name,
      "dist-tags": active ? { latest } : {},
      versions: versionDocs,
      ...(Object.keys(retractions).length ? { _sentinel: { retractions } } : {}),
    };
  }

  // ---- persistence (best-effort, mirrors AuditStore's style) ----

  private dirFor(name: string, version: string): string {
    return join(this.dir!, encodeURIComponent(name), encodeURIComponent(version));
  }

  private key(name: string, version: string): string {
    return `${name}\u0000${version}`;
  }

  private stateFile(): string {
    return join(this.dir!, ".registry-state.json");
  }

  private persistOperationalState(
    retractions: Map<string, RetractionTombstone>,
    downloads: Map<string, number>,
    windowHits: { age: number; downloads: number; both: number },
  ): void {
    if (!this.dir) return;
    mkdirSync(this.dir, { recursive: true });
    const decode = (key: string) => {
      const separator = key.indexOf("\u0000");
      return { name: key.slice(0, separator), version: key.slice(separator + 1) };
    };
    const state: OperationalState = {
      schema: 1,
      retractions: [...retractions].map(([key, tombstone]) => ({ ...decode(key), tombstone })),
      downloads: [...downloads].map(([key, count]) => ({ ...decode(key), count })),
      windowHits: { ...windowHits },
    };
    const temp = `${this.stateFile()}.${process.pid}.${randomUUID()}.tmp`;
    try {
      writeFileSync(temp, JSON.stringify(state, null, 2), { flag: "wx" });
      renameSync(temp, this.stateFile());
    } finally {
      try { unlinkSync(temp); } catch { /* rename succeeded or cleanup is best-effort */ }
    }
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
    const stateFile = this.stateFile();
    if (existsSync(stateFile)) {
      let state: OperationalState;
      try { state = JSON.parse(readFileSync(stateFile, "utf8")) as OperationalState; }
      catch { throw new Error("invalid private registry operational state: expected JSON"); }
      if (state?.schema !== 1 || !Array.isArray(state.retractions) || !Array.isArray(state.downloads) || !state.windowHits) {
        throw new Error("invalid private registry operational state: expected schema 1");
      }
      for (const row of state.retractions) this.retractions.set(this.key(row.name, row.version), structuredClone(row.tombstone));
      for (const row of state.downloads) this.downloads.set(this.key(row.name, row.version), row.count);
      this.windowHits = { ...state.windowHits };
    }
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

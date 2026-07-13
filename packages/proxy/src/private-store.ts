import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
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
  /** Dist-tag committed atomically with the immutable publication. */
  publishedTag?: string;
  publishedTagRevision?: number;
  /** Immutable ownership attribution captured when this version was accepted. */
  claimAtPublication?: Pick<VerifiedClaim, "namespace" | "domain" | "claimantPublicKey">;
  /** Original publish attestation document retained as immutable publication history. */
  attestations?: unknown;
}

export interface PrivatePackument {
  _id: string;
  _rev: string;
  name: string;
  "dist-tags": Record<string, string>;
  versions: Record<string, Record<string, unknown>>;
  time: Record<string, string>;
  _sentinel?: { retractions: Record<string, RetractionTombstone> };
}

export type { RetractionAdvisory, RetractionReason } from "@sentinel/core";

export interface RetractionTombstone {
  retractedAt: string;
  reason: RetractionReason;
  advisoryId: string;
}

interface OperationalState {
  schema: 1 | 2;
  retractions: { name: string; version: string; tombstone: RetractionTombstone }[];
  downloads: { name: string; version: string; count: number }[];
  windowHits: { age: number; downloads: number; both: number };
  distTags?: { name: string; tags: Record<string, { version: string | null; revision: number }> }[];
  deprecations?: { name: string; versions: Record<string, string | null> }[];
}

const RETRACTION_REASONS = new Set<RetractionReason>(["security", "withdrawn", "broken", "legal"]);

function validCoordinatePart(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && !value.includes("\u0000");
}

function nonnegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function canonicalInstant(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

interface Entry { meta: StoredVersion; tarball: Buffer; }

export class PublicationConflictError extends Error {}

/** Authoritative store for published private packages: tarball bytes + manifest + the
 * policy-independent Audit. Optional filesystem persistence (`<dir>/<enc>/<version>/`). */
export class PrivatePackageStore {
  private byName = new Map<string, Map<string, Entry>>();
  private retractions = new Map<string, RetractionTombstone>();
  private downloads = new Map<string, number>();
  /** Mutable overrides. Null is an explicit deletion of a publication tag. */
  private distTags = new Map<string, Record<string, { version: string | null; revision: number }>>();
  private deprecations = new Map<string, Record<string, string | null>>();
  private tagRevision = 0;
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
    distTag?: string | null;
    publishedAt?: string;
  }): StoredVersion {
    const publishedTag = v.distTag === undefined ? "latest" : v.distTag;
    if (publishedTag !== null && !/^[^\s/]+$/.test(publishedTag)) throw new Error("invalid dist-tag");
    if (this.getRetraction(v.name, v.version)) {
      throw new PublicationConflictError(`version identifier is permanently spent by retraction: ${v.name}@${v.version}`);
    }
    if (this.getVersion(v.name, v.version) || (this.dir && existsSync(this.dirFor(v.name, v.version)))) {
      throw new PublicationConflictError(`version already published: ${v.name}@${v.version}`);
    }
    const meta: StoredVersion = {
      name: v.name, version: v.version, integrity: v.integrity,
      manifest: v.manifest, audit: v.audit, actor: v.actor,
      publishedAt: v.publishedAt ?? new Date(this.now()).toISOString(),
      ...(publishedTag !== null ? { publishedTag, publishedTagRevision: ++this.tagRevision } : {}),
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
    distTag?: string | null;
    publishedAt?: string;
  }): StoredVersion {
    return this.publish(v);
  }

  retract(input: { name: string; version: string; reason: RetractionReason; retractedAt: string; advisoryId: string }): RetractionTombstone {
    return this.retractMany([input])[0]!;
  }

  retractMany(inputs: { name: string; version: string; reason: RetractionReason; retractedAt: string; advisoryId: string }[]): RetractionTombstone[] {
    const next = new Map(this.retractions);
    const tombstones = inputs.map((input) => {
      if (!this.getVersion(input.name, input.version)) throw new Error(`unknown native version ${input.name}@${input.version}`);
      const key = this.key(input.name, input.version);
      if (next.has(key)) throw new PublicationConflictError(`version already retracted: ${input.name}@${input.version}`);
      const tombstone: RetractionTombstone = { retractedAt: input.retractedAt, reason: input.reason, advisoryId: input.advisoryId };
      next.set(key, tombstone);
      return tombstone;
    });
    this.persistOperationalState(next, this.downloads, this.windowHits);
    this.retractions = next;
    return structuredClone(tombstones);
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

  /** Persist a monotonic floor imported from a deduplicating durable history DB. */
  ensureDownloadCountAtLeast(name: string, version: string, count: number): number {
    if (!this.getVersion(name, version)) throw new Error(`unknown native version ${name}@${version}`);
    if (!nonnegativeSafeInteger(count)) throw new Error("download count floor must be a nonnegative safe integer");
    const key = this.key(name, version);
    const current = this.downloads.get(key) ?? 0;
    if (count <= current) return current;
    const next = new Map(this.downloads);
    next.set(key, count);
    this.persistOperationalState(this.retractions, next, this.windowHits);
    this.downloads = next;
    return count;
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
    const time: Record<string, string> = {};
    for (const [v, entry] of versions) {
      const tombstone = this.retractions.get(this.key(name, v));
      if (tombstone) {
        retractions[v] = structuredClone(tombstone);
        continue;
      }
      versionDocs[v] = structuredClone(entry.meta.manifest);
      time[v] = entry.meta.publishedAt;
      if (cmpSemver(v, latest) > 0) latest = v;
    }
    const active = Object.keys(versionDocs).length > 0;
    const tags: Record<string, string> = {};
    const publications = [...versions].sort(([, a], [, b]) => a.meta.publishedAt.localeCompare(b.meta.publishedAt));
    const hasAtomicPublicationTags = publications.some(([, entry]) => entry.meta.publishedTag !== undefined);
    const tagRevisions: Record<string, number> = {};
    for (const [version, entry] of publications) {
      if (versionDocs[version] !== undefined && entry.meta.publishedTag) {
        tags[entry.meta.publishedTag] = version;
        tagRevisions[entry.meta.publishedTag] = entry.meta.publishedTagRevision ?? 0;
      }
    }
    for (const [tag, override] of Object.entries(this.distTags.get(name) ?? {})) {
      if (override.revision < (tagRevisions[tag] ?? 0)) continue;
      if (override.version === null) delete tags[tag];
      else if (versionDocs[override.version] !== undefined) tags[tag] = override.version;
    }
    if (active && !hasAtomicPublicationTags && !("latest" in tags) && this.distTags.get(name)?.latest?.version !== null) tags.latest = latest;
    const deprecations = this.deprecations.get(name) ?? {};
    for (const [version, message] of Object.entries(deprecations)) {
      const manifest = versionDocs[version];
      if (!manifest) continue;
      if (message === null) delete manifest.deprecated;
      else manifest.deprecated = message;
    }
    return {
      _id: name,
      _rev: this.revision(name),
      name,
      "dist-tags": active ? tags : {},
      versions: versionDocs,
      time,
      ...(Object.keys(retractions).length ? { _sentinel: { retractions } } : {}),
    };
  }

  setDistTag(name: string, tag: string, version: string): void {
    if (!/^[^\s/]+$/.test(tag)) throw new Error("invalid dist-tag");
    if (!this.getVersion(name, version) || this.getRetraction(name, version)) throw new Error(`unknown active native version ${name}@${version}`);
    const next = new Map(this.distTags);
    next.set(name, { ...(next.get(name) ?? {}), [tag]: { version, revision: ++this.tagRevision } });
    this.persistOperationalState(this.retractions, this.downloads, this.windowHits, next);
    this.distTags = next;
  }

  deleteDistTag(name: string, tag: string): boolean {
    if (!(tag in (this.packument(name)?.["dist-tags"] ?? {}))) return false;
    const tags = { ...(this.distTags.get(name) ?? {}), [tag]: { version: null, revision: ++this.tagRevision } };
    const next = new Map(this.distTags);
    next.set(name, tags);
    this.persistOperationalState(this.retractions, this.downloads, this.windowHits, next);
    this.distTags = next;
    return true;
  }

  updateDeprecations(name: string, revision: string, doc: Record<string, unknown>): string {
    if (revision !== this.revision(name)) throw new PublicationConflictError("packument revision conflict");
    const incoming = doc.versions as Record<string, Record<string, unknown>> | undefined;
    const versions = this.byName.get(name);
    if (!incoming || !versions || Object.keys(incoming).length !== versions.size) throw new Error("metadata update cannot add or remove versions");
    for (const [version, entry] of versions) {
      const candidate = incoming[version];
      if (!candidate) throw new Error("metadata update cannot add or remove versions");
      const currentDist = entry.meta.manifest.dist as { integrity?: unknown } | undefined;
      const candidateDist = candidate.dist as { integrity?: unknown } | undefined;
      if (currentDist?.integrity !== candidateDist?.integrity) throw new Error("metadata update cannot change version integrity");
    }
    const nextDeprecations = new Map(this.deprecations);
    nextDeprecations.set(name, Object.fromEntries([...versions].map(([version]) => {
      const deprecated = incoming[version]!.deprecated;
      return [version, typeof deprecated === "string" ? deprecated : null];
    })));
    this.persistOperationalState(this.retractions, this.downloads, this.windowHits, this.distTags, nextDeprecations);
    this.deprecations = nextDeprecations;
    return this.revision(name);
  }

  revision(name: string): string {
    const versions = this.byName.get(name);
    if (!versions) return "0-missing";
    const state = {
      versions: [...versions].map(([version, entry]) => [version, entry.meta.integrity,
        Object.hasOwn(this.deprecations.get(name) ?? {}, version)
          ? this.deprecations.get(name)![version]
          : entry.meta.manifest.deprecated ?? null]),
      tags: this.distTags.get(name) ?? {},
      retractions: [...this.retractions].filter(([key]) => key.startsWith(`${name}\u0000`)),
    };
    return `1-${createHash("sha256").update(JSON.stringify(state)).digest("hex").slice(0, 16)}`;
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
    distTags: Map<string, Record<string, { version: string | null; revision: number }>> = this.distTags,
    deprecations: Map<string, Record<string, string | null>> = this.deprecations,
  ): void {
    if (!this.dir) return;
    mkdirSync(this.dir, { recursive: true });
    const decode = (key: string) => {
      const separator = key.indexOf("\u0000");
      return { name: key.slice(0, separator), version: key.slice(separator + 1) };
    };
    const state: OperationalState = {
      schema: 2,
      retractions: [...retractions].map(([key, tombstone]) => ({ ...decode(key), tombstone })),
      downloads: [...downloads].map(([key, count]) => ({ ...decode(key), count })),
      windowHits: { ...windowHits },
      distTags: [...distTags].map(([name, tags]) => ({ name, tags })),
      deprecations: [...deprecations].map(([name, versions]) => ({ name, versions })),
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
      if ((state?.schema !== 1 && state?.schema !== 2) || !Array.isArray(state.retractions) || !Array.isArray(state.downloads) ||
          !state.windowHits || typeof state.windowHits !== "object") {
        throw new Error("invalid private registry operational state: expected schema 1");
      }
      const seenRetractions = new Set<string>();
      for (const row of state.retractions) {
        const tombstone = row?.tombstone;
        if (!validCoordinatePart(row?.name) || !validCoordinatePart(row?.version) || !tombstone ||
            !canonicalInstant(tombstone.retractedAt) || !RETRACTION_REASONS.has(tombstone.reason) ||
            !validCoordinatePart(tombstone.advisoryId)) {
          throw new Error("invalid private registry operational state: malformed retraction");
        }
        const key = this.key(row.name, row.version);
        if (seenRetractions.has(key)) throw new Error("invalid private registry operational state: duplicate retraction");
        seenRetractions.add(key);
        this.retractions.set(key, structuredClone(tombstone));
      }
      const seenDownloads = new Set<string>();
      for (const row of state.downloads) {
        if (!validCoordinatePart(row?.name) || !validCoordinatePart(row?.version) || !nonnegativeSafeInteger(row?.count)) {
          throw new Error("invalid private registry operational state: malformed download count");
        }
        const key = this.key(row.name, row.version);
        if (seenDownloads.has(key)) throw new Error("invalid private registry operational state: duplicate download count");
        seenDownloads.add(key);
        this.downloads.set(key, row.count);
      }
      const hits = state.windowHits as Record<string, unknown>;
      if (!nonnegativeSafeInteger(hits.age) || !nonnegativeSafeInteger(hits.downloads) || !nonnegativeSafeInteger(hits.both)) {
        throw new Error("invalid private registry operational state: malformed window-hit counters");
      }
      this.windowHits = { age: hits.age, downloads: hits.downloads, both: hits.both };
      if (state.schema === 2) {
        if (!Array.isArray(state.distTags)) throw new Error("invalid private registry operational state: malformed dist-tags");
        for (const row of state.distTags) {
          if (!validCoordinatePart(row?.name) || !row.tags || typeof row.tags !== "object" || Array.isArray(row.tags) ||
              Object.entries(row.tags).some(([tag, override]) => !validCoordinatePart(tag) || !override || typeof override !== "object" ||
                !nonnegativeSafeInteger(override.revision) || (override.version !== null && !validCoordinatePart(override.version)))) {
            throw new Error("invalid private registry operational state: malformed dist-tags");
          }
          this.distTags.set(row.name, { ...row.tags });
          for (const override of Object.values(row.tags)) this.tagRevision = Math.max(this.tagRevision, override.revision);
        }
        if (state.deprecations !== undefined && !Array.isArray(state.deprecations)) {
          throw new Error("invalid private registry operational state: malformed deprecations");
        }
        for (const row of state.deprecations ?? []) {
          if (!validCoordinatePart(row?.name) || !row.versions || typeof row.versions !== "object" || Array.isArray(row.versions) ||
              Object.entries(row.versions).some(([version, message]) => !validCoordinatePart(version) || (message !== null && typeof message !== "string"))) {
            throw new Error("invalid private registry operational state: malformed deprecations");
          }
          this.deprecations.set(row.name, { ...row.versions });
        }
      }
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
          this.tagRevision = Math.max(this.tagRevision, meta.publishedTagRevision ?? 0);
        } catch {
          /* skip a corrupt entry */
        }
      }
    }
  }
}

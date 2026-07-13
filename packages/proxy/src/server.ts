import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import express, { type Request, type Response } from "express";
import { rateLimit } from "express-rate-limit";
import {
  runAudit,
  score,
  POLICY_SYNTHESIZED_RULE_IDS,
  policyHashOf,
  claimCorpusHashOfBytes,
  retractionCorpusHashOfBytes,
  parseRetractionCorpus,
  EMPTY_RETRACTION_CORPUS,
  integrityOf,
  integrityOfAlgo,
  aggregateTree,
  treeGateOf,
  publishGateOf,
  retractionWindowOf,
  verdictAtOrAbove,
  NPM_SIGNING_KEYS,
  remediate,
  parsePolicy,
  type Audit,
  type AuditReport,
  type EnterprisePolicy,
  type PackageMeta,
  type TreePackageRow,
  type TreeAuditResult,
  type NpmSigningKey,
  type ProvenanceTrustMaterial,
  type ReleaseContext,
  type Advisory,
  type VulnAdvisory,
  type ScoredFinding,
  type RetractionAdvisory,
  type RetractionCorpus,
  type RetractionReason,
} from "@sentinel/core";
import { AuditStore } from "./store.js";
import { resolvePublishTime, cooldownDecision, applyCooldown, blockOverlay } from "./cooldown.js";
import {
  cmpSemver,
  HttpError,
  previousVersion,
  type Upstream,
  type UpstreamPackument,
} from "./upstream.js";
import { ApprovalStore, type Approval } from "./approvals.js";
import { reconcileApproval, type ApprovalState } from "./reconcile.js";
import { PrivatePackageStore, PublicationConflictError, type RetractionTombstone } from "./private-store.js";
import { parsePublishBody, publishTokenValid } from "./private.js";
import {
  EMPTY_CLAIM_CORPUS,
  claimForPackage,
  isNativeSource,
  normalizePackageName,
  normalizeRegistryReadName,
  source,
  trustedPublisherAuthorized,
  validateClaimCorpus,
  type ClaimCorpus,
} from "./resolution.js";
import { ViolationStore, type ViolationInput } from "./violations.js";
import { ApprovalRequestStore } from "./approval-requests.js";
import { makeAuthz } from "./authz.js";
import { isLoopbackHost } from "./net-config.js";
import type { HistoryDb } from "./history-db.js";
import type { RateLimiter } from "./rate-limit.js";

export type ProxyPolicy = "observe" | "block";

export interface ServerOptions {
  upstream: Upstream;
  store: AuditStore;
  approvals: ApprovalStore;
  /** The signed scoring policy this proxy serves under. */
  enterprisePolicy: EnterprisePolicy;
  /** Hash of the active policy (raw-bytes for loaded, canonical for default). */
  policyHash?: string;
  /** `observe` always serves (audits + headers only); `block` 403s on a block verdict. */
  policy?: ProxyPolicy;
  /** Directory containing the dashboard `index.html`. */
  publicDir?: string;
  /** Authoritative store for published private packages (ADR-0010). */
  privateStore: PrivatePackageStore;
  /** Verified offline claim data. The executable loads this from signed bytes; embedders supply parsed data. */
  claimCorpus?: ClaimCorpus;
  /** Hash of the verified raw corpus bytes; canonical in-memory hash for embedders. */
  claimCorpusHash?: string;
  /** Verified offline retraction data for fleet-wide tombstone propagation. */
  retractionCorpus?: RetractionCorpus;
  /** Hash of the verified raw retraction-corpus bytes. */
  retractionCorpusHash?: string;
  /** Valid bearer tokens for publishing; empty ⇒ publishing disabled. */
  publishTokens?: string[];
  /** Trusted npm registry signing keys (default: bundled npm keys). */
  signingKeys?: NpmSigningKey[];
  /** Pinned Sigstore trust material. undefined ⇒ bundled default; null ⇒ disabled. */
  trustMaterial?: ProvenanceTrustMaterial | null;
  /** Runtime-violation telemetry store (Phase 10). */
  violations: ViolationStore;
  /** Pending approval requests store (agent asks, human grants) — Phase 11. */
  approvalRequests: ApprovalRequestStore;
  /** Operator Ed25519 public key PEM. Undefined ⇒ control-plane auth disabled (open mode). */
  authPublicKey?: string;
  /** Durable observability store (Phase 15). Undefined ⇒ history/metrics disabled. */
  history?: HistoryDb;
  /** Operator-supplied known-malicious advisories, merged with the bundled corpus (Phase 21). */
  advisories?: Advisory[];
  /** Operator-supplied known-vulnerability advisories, merged with the bundled corpus (Phase 22). */
  vulnerabilities?: VulnAdvisory[];
  /** Public base URL for rewritten dist.tarball links (ADR-0036). Undefined ⇒ loopback-Host-derived only. */
  publicBaseUrl?: string;
  /** Max distinct packages per audit-tree request (ADR-0037). Undefined ⇒ 5000. */
  maxTreePackages?: number;
  /** Opt-in per-source rate limiter for expensive open endpoints (ADR-0037). Undefined ⇒ unlimited. */
  rateLimiter?: RateLimiter;
  /** Mandatory publish limiter. Undefined ⇒ 60 requests per source per minute. */
  publishRateLimit?: { limit: number; windowMs: number };
  /** Opt-in auto-quarantine on confirmed violations (ADR-0040). Requires auth. Default off. */
  autoQuarantine?: boolean;
  /** Decompression-bomb extraction caps (ADR-0039). Undefined ⇒ core defaults. */
  extractLimits?: { maxUnpackedBytes?: number; maxFileCount?: number };
  /** Max buffered npm publish JSON bytes. Default 64 MiB. */
  maxPublishBytes?: number;
  /** Test seam for the synchronous publish scanner. Production defaults to core runAudit. */
  publishAudit?: typeof runAudit;
  /** Injectable clock (ms) for the release-cooldown overlay. Default Date.now. */
  now?: () => number;
}

const TARBALL_RE = /^(.+)\/-\/([^/]+\.tgz)$/;

/** Derive the release-vs-history context for a version from its packument (Phase 16). Pure. */
export function buildReleaseContext(pm: UpstreamPackument, version: string): ReleaseContext {
  const prev = previousVersion(Object.keys(pm.versions), version);
  const rc: ReleaseContext = { versionCount: Object.keys(pm.versions).length };
  if (pm.time?.[version]) rc.currentPublishedAt = pm.time[version];
  if (prev) {
    rc.previousVersion = prev;
    rc.previousMaintainers = pm.versions[prev]?.maintainers;
    if (pm.time?.[prev]) rc.previousPublishedAt = pm.time[prev];
  }
  return rc;
}

/** Run `fn` over `items` with at most `limit` in flight; preserves input order. */
async function mapPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/**
 * Base URL for rewritten dist.tarball links: the configured public base, or a
 * loopback-Host-derived fallback for zero-config local dev. A non-loopback
 * Host with no configured base is refused — the rewrite would otherwise point
 * npm at whatever origin the Host header claims (ADR-0036).
 */
function baseUrlFor(req: Request, configured: string | undefined): string {
  if (configured) return configured;
  const host = req.get("host") ?? "";
  if (isLoopbackHost(host)) return `${req.protocol}://${host}`;
  throw new HttpError(421, `refusing to derive tarball URLs from non-loopback Host "${host}" — set SENTINEL_PUBLIC_BASE_URL`);
}

export function createServer(opts: ServerOptions) {
  const { upstream, store, approvals, violations, approvalRequests } = opts;
  const history = opts.history;
  const enterprisePolicy = opts.enterprisePolicy;
  const policyHash = opts.policyHash ?? policyHashOf(enterprisePolicy);
  const policy: ProxyPolicy = opts.policy ?? "observe";
  const privateStore = opts.privateStore ?? new PrivatePackageStore();
  const claimCorpus = opts.claimCorpus ?? EMPTY_CLAIM_CORPUS;
  validateClaimCorpus(claimCorpus);
  const claimCorpusHash = opts.claimCorpusHash ?? claimCorpusHashOfBytes(Buffer.from(JSON.stringify(claimCorpus)));
  const retractionCorpus = opts.retractionCorpus ?? EMPTY_RETRACTION_CORPUS;
  parseRetractionCorpus(Buffer.from(JSON.stringify(retractionCorpus)));
  const retractionCorpusHash = opts.retractionCorpusHash ?? retractionCorpusHashOfBytes(Buffer.from(JSON.stringify(retractionCorpus)));
  const corpusRetractions = new Map(
    retractionCorpus.advisories.map((advisory) => [`${advisory.name}\u0000${advisory.version}`, advisory] as const),
  );
  const publishTokens = opts.publishTokens ?? [];
  const signingKeys = opts.signingKeys ?? NPM_SIGNING_KEYS;
  const advisories = opts.advisories;
  const vulnerabilities = opts.vulnerabilities;
  const publicBaseUrl = opts.publicBaseUrl;
  const maxTreePackages = opts.maxTreePackages ?? 5000;
  const extractLimits = opts.extractLimits;
  const now = opts.now ?? Date.now;
  const publishAudit = opts.publishAudit ?? runAudit;
  const authz = makeAuthz(opts.authPublicKey);
  // Auto-quarantine only when the operator opted in AND auth is enabled (so every
  // quarantine is attributable to a verified token). Open mode never quarantines.
  const autoQuarantineEnabled = Boolean(opts.autoQuarantine) && authz.enabled;
  const app = express();
  app.disable("x-powered-by");
  const jsonSmall = express.json({ limit: "1mb" });
  app.use((req, res, next) => (req.method === "PUT" ? next() : jsonSmall(req, res, next)));
  const jsonPublish = express.json({ limit: opts.maxPublishBytes ?? 64 * 1024 * 1024 });

  const registrySource = (name: string) => source(name, enterprisePolicy, claimCorpus);
  const isNativeName = (name: string) => isNativeSource(registrySource(name));
  // Audit bytes are policy/corpus-independent cache data. A report represents
  // the decision context at response time, so cached audits deliberately carry
  // the currently active corpus identity rather than their original cache time.
  const withClaimCorpus = (report: AuditReport): AuditReport => ({
    ...report,
    policy: {
      ...report.policy,
      claimCorpus: { version: claimCorpus.version, hash: claimCorpusHash },
      retractionCorpus: { version: retractionCorpus.version, hash: retractionCorpusHash },
    },
  });
  const scoreAudit = (audit: Audit, activePolicy = enterprisePolicy, activePolicyHash = policyHash): AuditReport =>
    withClaimCorpus(score(audit, activePolicy, activePolicyHash));

  const rateLimiter = opts.rateLimiter;
  const rateGate: express.RequestHandler = rateLimiter
    ? (req, res, next) => {
        const key = req.socket.remoteAddress ?? "unknown";
        const { allowed, retryAfterSec } = rateLimiter.check(key);
        if (allowed) return next();
        res.setHeader("Retry-After", String(retryAfterSec));
        return res.status(429).json({ error: "rate limit exceeded — retry later or raise SENTINEL_RATE_LIMIT_RPM" });
      }
    : (_req, _res, next) => next();
  const publishRateGate = rateLimit({
    windowMs: opts.publishRateLimit?.windowMs ?? 60_000,
    limit: opts.publishRateLimit?.limit ?? 60,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "publish rate limit exceeded — retry later" },
  });

  // Transient concurrency dedupe: concurrent uncached public audits for the same
  // name@version share one pipeline. The integrity-keyed `store` stays the durable
  // cache (invariant #4); this map lives only within the overlapping-request window.
  const inFlight = new Map<string, Promise<{ report: AuditReport; tarball: Buffer }>>();

  /** Audit a specific version, using the verdict cache (integrity-keyed). */
  async function auditVersion(
    pkg: string,
    version: string,
    providedTarball?: Buffer,
  ): Promise<{ report: AuditReport; tarball: Buffer }> {
    pkg = normalizeRegistryReadName(pkg);
    // Native names are authoritative — NEVER consult public upstream.
    if (isNativeName(pkg)) {
      const cachedAudit = privateStore.getAudit(pkg, version);
      const tarball = privateStore.getTarball(pkg, version);
      if (!cachedAudit || !tarball) throw new HttpError(404, `private package not found ${pkg}@${version}`);
      const report = scoreAudit(cachedAudit);
      store.put(report); // populate verdict store so /-/approvals can find the integrity
      return { report, tarball };
    }
    // A caller that already holds the bytes skips the fetch entirely — no coalescing needed.
    if (providedTarball) return auditPublicUncached(pkg, version, providedTarball);

    // Coalesce concurrent uncached fetches for the same coordinate.
    const key = `${pkg}@${version}`;
    const existing = inFlight.get(key);
    if (existing) return existing;
    const p = auditPublicUncached(pkg, version, undefined).finally(() => inFlight.delete(key));
    inFlight.set(key, p);
    return p;
  }

  async function auditPublicUncached(
    pkg: string,
    version: string,
    providedTarball: Buffer | undefined,
  ): Promise<{ report: AuditReport; tarball: Buffer }> {
    const pm = await upstream.getPackument(pkg);
    const vmeta = pm.versions[version];
    if (!vmeta) throw new HttpError(404, `unknown version ${pkg}@${version}`);

    const tarball = providedTarball ?? (await upstream.getTarball(pkg, version));
    // Cache and report by the ACTUAL bytes hash; the claimed integrity goes into
    // runAudit for the tamper check (ADR-0022).
    const actualIntegrity = integrityOf(tarball);

    const cached = store.get(actualIntegrity);
    if (cached) return { report: withClaimCorpus(cached.report), tarball };

    const prev = previousVersion(Object.keys(pm.versions), version);
    const baselineTarball = prev ? await upstream.getTarball(pkg, prev) : undefined;
    const attestations = vmeta.hasProvenance ? await upstream.getAttestations(pkg, version) : null;

    const meta: Omit<PackageMeta, "unpackedSize" | "fileCount" | "signature" | "provenance"> = {
      name: pkg,
      version,
      author: vmeta.author,
      maintainers: vmeta.maintainers,
      license: vmeta.license,
      hasInstallScripts: vmeta.hasInstallScripts,
      integrity: vmeta.integrity ?? actualIntegrity,
    };

    const releaseContext = buildReleaseContext(pm, version);
    const audit = await runAudit({
      meta, tarball, baselineTarball,
      signatures: vmeta.signatures, hasProvenance: vmeta.hasProvenance,
      attestations, signingKeys, trustMaterial: opts.trustMaterial,
      releaseContext, advisories: [...(advisories ?? []), ...retractionCorpus.advisories], vulnerabilities, extractLimits,
    });
    const report = scoreAudit(audit);
    store.put(report);
    return { report, tarball };
  }

  /** Overlay a quarantine on a served report: inject a critical runtime-violation finding + force block. */
  function applyQuarantine(report: AuditReport): AuditReport {
    const rec = violations.get(report.meta.integrity);
    if (!rec?.quarantined) return report;
    const finding: ScoredFinding = {
      ruleId: "runtime-violation", category: "install-script" as const, severity: "critical" as const,
      message: `runtime violation: ${rec.kind} access to ${rec.target ?? rec.deniedResource ?? "a denied resource"} blocked at install time — build quarantined`,
      onChangedFile: false, evidence: [], weight: 0, waived: false,
    };
    return blockOverlay(report, finding);
  }

  function retractionFor(report: AuditReport): RetractionAdvisory | undefined {
    const advisory = privateStore.getRetractionAdvisory(report.meta.name, report.meta.version)
      ?? corpusRetractions.get(`${report.meta.name}\u0000${report.meta.version}`);
    return advisory?.integrity === report.meta.integrity ? advisory : undefined;
  }

  /** Authoritative-fact overlay: immutable report copy; security blocks, other reasons warn. */
  function applyRetraction(report: AuditReport): { report: AuditReport; tombstone?: RetractionTombstone } {
    const advisory = retractionFor(report);
    if (!advisory) return { report };
    const finding: ScoredFinding = {
      ruleId: "known-advisory", category: "metadata", severity: advisory.severity,
      message: `\`${advisory.name}@${advisory.version}\` was retracted (${advisory.reason}) in advisory ${advisory.id}.`,
      onChangedFile: false, evidence: [], weight: 0, waived: false,
    };
    const verdict = advisory.reason === "security"
      ? "block" as const
      : report.verdict === "allow" ? "warn" as const : report.verdict;
    const alreadyPresent = report.findings.some((candidate) => candidate.ruleId === "known-advisory" && candidate.message.includes(advisory.id));
    return {
      report: { ...report, verdict, findings: alreadyPresent ? report.findings : [finding, ...report.findings] },
      tombstone: { retractedAt: advisory.retractedAt, reason: advisory.reason, advisoryId: advisory.id },
    };
  }

  /** Resolve the release-cooldown decision for a coordinate (ADR — release-cooldown overlay).
   *  No-op ({ block: false }) when the policy has no `releaseCooldown`, so this is inert by
   *  default. Publish-time origin mirrors the trust boundary elsewhere in this file: a claimed
   *  name resolves from the (authoritative) private store, everything else from the public
   *  packument's `time` map. */
  async function cooldownFor(pkg: string, version: string): Promise<{ block: boolean; reason?: string }> {
    if (!enterprisePolicy.releaseCooldown) return { block: false };
    let publishTime: string | null = null;
    if (isNativeName(pkg)) {
      publishTime = resolvePublishTime({ isPrivate: true, privatePublishedAt: privateStore.getVersion(pkg, version)?.publishedAt });
    } else {
      try {
        const pm = await upstream.getPackument(pkg);
        publishTime = resolvePublishTime({ isPrivate: false, publicTime: pm.time?.[version] });
      } catch {
        publishTime = null;
      }
    }
    return cooldownDecision({ policy: enterprisePolicy, name: pkg, publishTime, now: now() });
  }

  function gateAndSend(
    res: Response, pkg: string, version: string, report: AuditReport, tarball: Buffer, isPrivate: boolean,
    cooldown: { block: boolean; reason?: string }, onServe?: () => void,
  ): Response | void {
    const retraction = applyRetraction(report);
    report = applyCooldown(applyQuarantine(retraction.report), cooldown);
    const rec = reconcile(report);
    res.setHeader("x-sentinel-score", String(report.score));
    res.setHeader("x-sentinel-verdict", report.verdict);
    res.setHeader("x-sentinel-violations", String(violations.get(report.meta.integrity) ? 1 : 0));
    res.setHeader("x-sentinel-findings", String(report.findings.length));
    res.setHeader("x-sentinel-capabilities", String(report.capabilities.length));
    res.setHeader("x-sentinel-approval", rec.state);
    res.setHeader("x-sentinel-policy", report.policy.version);
    res.setHeader("x-sentinel-claim-corpus", report.policy.claimCorpus?.version ?? "empty");
    res.setHeader("x-sentinel-retraction-corpus", report.policy.retractionCorpus?.version ?? "empty");
    // legacy persisted audits may predate the provenance field
    res.setHeader("x-sentinel-provenance", report.meta.provenance ?? "unknown");
    if (isPrivate) res.setHeader("x-sentinel-private", "true");
    if (retraction.tombstone) {
      return res.status(410).json({
        error: "package version retracted", package: `${pkg}@${version}`, ...retraction.tombstone,
      });
    }
    if (policy === "block") {
      if (report.verdict === "block") {
        return res.status(403).json({ error: "blocked by Sentinel policy", package: `${pkg}@${version}`,
          score: report.score, verdict: report.verdict,
          findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })) });
      }
      if (rec.state === "denied") return res.status(403).json({ error: "approval denied by Sentinel policy", package: `${pkg}@${version}` });
      if (rec.state === "required") return res.status(403).json({ error: "approval required by Sentinel policy",
        package: `${pkg}@${version}`, approvalRequired: rec.approvalRequired,
        findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })) });
    }
    onServe?.();
    res.setHeader("content-type", "application/octet-stream");
    return res.send(tarball);
  }

  function reconcile(report: AuditReport) {
    const explicit = approvals.get(report.meta.integrity);
    let priorApproved = approvals.latestApprovedFor(report.meta.name);
    // Discard prior approval if it is for a version >= the one being reconciled
    // to prevent forward inheritance (a newer approval must not cover older versions).
    if (priorApproved && cmpSemver(priorApproved.version, report.meta.version) >= 0) {
      priorApproved = undefined;
    }
    return reconcileApproval({ capabilities: report.capabilities, explicit, priorApproved });
  }

  // ---- internal API (the `/-/` namespace mirrors npm's reserved prefix) ----

  app.get("/-/health", (_req, res) => {
    res.json({ ok: true, upstream: upstream.name, policy });
  });

  // Pre-install verdict for the CLI / dashboard. No bytes served.
  app.get(/^\/-\/audit\/(.+)\/([^/]+)$/, async (req, res) => {
    const pkg = decodeURIComponent(req.params[0] ?? "");
    const version = req.params[1] ?? "";
    try {
      const { report } = await auditVersion(pkg, version);
      const cd = await cooldownFor(pkg, version);
      res.json(applyCooldown(applyRetraction(report).report, cd));
    } catch (err) {
      sendError(res, err);
    }
  });

  /** Newest prior version (semver, strictly older, most-recent 10) that audits `allow`.
   *  Claimed names are authoritative private — mirrors auditVersion/the packument route:
   *  NEVER consult public upstream for a claimed name (invariant #7 — enumerating a
   *  claimed name against public npm is dependency-confusion reconnaissance). */
  async function findLastKnownGood(pkg: string, version: string): Promise<{ version: string; score: number } | null> {
    let priors: string[];
    try {
      const allVersions = isNativeName(pkg)
        ? privateStore.versions(pkg)
        : Object.keys((await upstream.getPackument(pkg)).versions);
      priors = allVersions.filter((v) => cmpSemver(v, version) < 0).sort(cmpSemver).reverse().slice(0, 10);
    } catch {
      return null;
    }
    for (const v of priors) {
      try {
        const { report } = await auditVersion(pkg, v);
        const cd = await cooldownFor(pkg, v);
        const overlaid = applyCooldown(report, cd);
        if (overlaid.verdict === "allow") return { version: v, score: overlaid.score };
      } catch { /* skip an unauditeable prior version */ }
    }
    return null;
  }

  // Explain a verdict + suggest remediation + walk back to the last known-good release.
  // Off the inline gate (invariant #3) — this route is expected to be slower.
  app.get(/^\/-\/explain\/(.+)\/([^/]+)$/, rateGate, async (req, res) => {
    const pkg = decodeURIComponent(req.params[0] ?? "");
    const version = req.params[1] ?? "";
    try {
      const { report } = await auditVersion(pkg, version);
      const cd = await cooldownFor(pkg, version);
      const overlaid = applyCooldown(applyRetraction(report).report, cd);
      const remediation = remediate(overlaid);
      const lastKnownGood = await findLastKnownGood(pkg, version);
      res.json({ report: overlaid, remediation, lastKnownGood });
    } catch (err) {
      sendError(res, err);
    }
  });

  app.get("/-/audits", (_req, res) => {
    res.json({ stats: store.stats(), audits: store.recent(50).map((s) => s.report) });
  });

  // Durable audit history / observability reads (Phase 15). Open — not role-gated
  // (Phase 12 authz gates only mutating routes). 501 when no HistoryDb is configured,
  // never a silent empty response.
  const disabled = (res: import("express").Response) => res.status(501).json({ enabled: false });

  app.get("/-/metrics", (_req, res) => {
    if (!history) return disabled(res);
    res.json({ summary: history.summary(), trends: history.trends(), topFlagged: history.topFlagged() });
  });

  app.get("/-/history", (req, res) => {
    if (!history) return disabled(res);
    const q = req.query;
    // Coerce only string query params; an array/object param (?verdict=a&verdict=b,
    // ?name[$ne]=) becomes undefined rather than reaching node:sqlite and 500ing.
    const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
    const numStr = str(q.limit);
    // Clamp into [1, 500]: Math.max floors a negative/zero, since SQLite LIMIT -1 = unbounded.
    const limit = numStr ? Math.max(1, Math.min(Number(numStr) || 50, 500)) : 50;
    const offStr = str(q.offset);
    const offset = offStr ? Math.max(0, Number(offStr) || 0) : 0;
    res.json({
      history: history.history({ verdict: str(q.verdict), name: str(q.name), limit, offset }),
    });
  });

  app.get("/-/violations/timeline", (_req, res) => {
    if (!history) return disabled(res);
    res.json({ timeline: history.violationTimeline() });
  });

  // Policy authoring impact preview (Phase 20): dry-run a candidate policy over the
  // stored audit history via score()'s determinism (invariant #1) — never applied,
  // stored, or signed. Requires a HistoryDb; 501 otherwise (same contract as the rest
  // of this observability block).
  app.post("/-/policy/preview", rateGate, (req, res) => {
    if (!history) return disabled(res);
    let candidate: EnterprisePolicy;
    try {
      candidate = parsePolicy(Buffer.from(JSON.stringify((req.body as { policy?: unknown }).policy ?? {})));
    } catch {
      return res.status(400).json({ error: "invalid candidate policy" });
    }
    const transitions = { allowToWarn: 0, allowToBlock: 0, warnToAllow: 0, warnToBlock: 0, blockToAllow: 0, blockToWarn: 0, unchanged: 0 };
    const changed: { name: string; version: string; from: string; to: string; fromScore: number; toScore: number }[] = [];
    for (const report of history.allReports()) {
      let to;
      try {
        // score() synthesizes dependency-confusion + provenance-identity findings
        // (packages/core/src/score.ts) and appends them; the stored report's
        // findings already contain them from the original scoring, so strip before
        // the re-score or they double-count (a real weight for dep-confusion).
        const findings = report.findings.filter((f) => !POLICY_SYNTHESIZED_RULE_IDS.has(f.ruleId));
        to = scoreAudit({ ...report, findings } as unknown as Audit, candidate, policyHashOf(candidate));
      } catch {
        continue; // skip an un-scoreable stored report (invariant #6)
      }
      const from = report.verdict;
      if (to.verdict === from) {
        transitions.unchanged++;
        continue;
      }
      const key = `${from}To${to.verdict[0]!.toUpperCase()}${to.verdict.slice(1)}` as keyof typeof transitions;
      if (key in transitions) transitions[key]++;
      changed.push({ name: report.meta.name, version: report.meta.version, from, to: to.verdict, fromScore: report.score, toScore: to.score });
    }
    const rank: Record<string, number> = { block: 0, warn: 1, allow: 2 };
    changed.sort((a, b) => (rank[a.to]! - rank[b.to]!) || (a.toScore - b.toScore));
    res.json({ enabled: true, total: transitions.unchanged + changed.length, transitions, changed: changed.slice(0, 100) });
  });

  // Whole-tree audit: fan out over the integrity-cached auditVersion path and
  // roll up a policy-gated aggregate (ADR-0020). Batch endpoint, not the gate path.
  app.post("/-/audit-tree", rateGate, async (req, res) => {
    const body = req.body as { packages?: unknown; failOnError?: unknown };
    if (!body || !Array.isArray(body.packages)) {
      return res.status(400).json({ error: "expected { packages: [{ name, version, integrity? }] }" });
    }
    const coords = body.packages as { name?: unknown; version?: unknown; integrity?: unknown }[];
    for (const cc of coords) {
      if (!cc || typeof cc.name !== "string" || typeof cc.version !== "string") {
        return res.status(400).json({ error: "each package needs a string name and version" });
      }
    }
    const failOnError = body.failOnError === true;
    // Dedupe by name@version before fanning out — auditVersion is deterministic,
    // so auditing a distinct coordinate once and re-expanding to per-request rows
    // is behavior-neutral (ADR-0037).
    const validCoords = coords as { name: string; version: string; integrity?: string }[];
    const distinctKeys: string[] = [];
    const distinctByKey = new Map<string, { name: string; version: string; integrity?: string }>();
    for (const co of validCoords) {
      const key = `${co.name}@${co.version}`;
      if (!distinctByKey.has(key)) { distinctByKey.set(key, co); distinctKeys.push(key); }
    }
    if (distinctKeys.length > maxTreePackages) {
      return res.status(413).json({
        error: `audit-tree request has ${distinctKeys.length} distinct packages, which exceeds the limit of ${maxTreePackages} (raise SENTINEL_MAX_TREE_PACKAGES)`,
      });
    }
    const distinctRows: TreePackageRow[] = await mapPool(
      distinctKeys.map((k) => distinctByKey.get(k)!),
      8,
      async (co) => {
        try {
          const { report: audited, tarball } = await auditVersion(co.name, co.version);
          const quarantined = applyQuarantine(applyRetraction(audited).report);
          const cd = await cooldownFor(co.name, co.version);
          const report = applyCooldown(quarantined, cd);
          const claimed = typeof co.integrity === "string" ? co.integrity : null;
          // Verify same-algorithm: recompute the SERVED bytes' digest in the lockfile's
          // own algorithm so a legacy sha1/sha256 pin is genuinely checked (not skipped —
          // skipping would fail-open) and never false-flagged against our sha512 recompute.
          // A truly-unknown algorithm can't be recomputed, so it's left unverified (skip).
          const algo = claimed?.split("-", 1)[0];
          const mismatch =
            claimed !== null && (algo === "sha1" || algo === "sha256" || algo === "sha512")
              ? claimed !== integrityOfAlgo(tarball, algo)
              : false;
          return {
            name: co.name, version: co.version,
            status: mismatch ? "block" as const : report.verdict,
            score: report.score,
            topFinding: mismatch
              ? `lockfile-integrity-mismatch: lockfile pins ${co.integrity!.slice(0, 20)}… but the registry serves a different hash`
              : (report.findings[0]?.message ?? null),
            topFindingRuleId: report.findings[0]?.ruleId ?? null,
            error: null, provenance: report.meta.provenance, integrityMismatch: mismatch,
            vulnerabilities: report.findings.filter((f) => f.ruleId === "known-vulnerability").length,
          };
        } catch (err) {
          return {
            name: co.name, version: co.version, status: "error" as const,
            score: null, topFinding: null, topFindingRuleId: null, error: (err as Error)?.message ?? "audit failed",
            provenance: null, integrityMismatch: false,
          };
        }
      },
    );
    const rowByKey = new Map<string, TreePackageRow>();
    for (const row of distinctRows) rowByKey.set(`${row.name}@${row.version}`, row);
    const rows: TreePackageRow[] = validCoords.map((co) => rowByKey.get(`${co.name}@${co.version}`)!);
    const aggregate = aggregateTree(rows, treeGateOf(enterprisePolicy), { failOnError });
    const result: TreeAuditResult = {
      aggregate, packages: rows, policyHash,
      claimCorpus: { version: claimCorpus.version, hash: claimCorpusHash },
      retractionCorpus: { version: retractionCorpus.version, hash: retractionCorpusHash },
    };
    res.json(result);
  });

  app.get(/^\/-\/manifest\/(.+)\/([^/]+)$/, async (req, res) => {
    const pkg = decodeURIComponent(req.params[0] ?? "");
    const version = req.params[1] ?? "";
    try {
      const { report } = await auditVersion(pkg, version);
      const cd = await cooldownFor(pkg, version);
      const overlaid = applyCooldown(applyRetraction(report).report, cd);
      const rec = reconcile(overlaid);
      res.json({
        meta: overlaid.meta, score: overlaid.score, verdict: overlaid.verdict,
        findings: overlaid.findings, capabilities: overlaid.capabilities,
        capabilityDelta: overlaid.capabilityDelta,
        approvalRequired: rec.approvalRequired, approvalState: rec.state,
        inheritedFrom: rec.inheritedFrom,
      });
    } catch (err) {
      sendError(res, err);
    }
  });

  app.post("/-/approvals", rateGate, authz.requireRole(["operator"]), (req, res) => {
    const body = Array.isArray(req.body) ? req.body : [req.body];
    const recorded: Approval[] = [];
    try {
      for (const d of body) {
        if (!d?.integrity || (d.decision !== "approved" && d.decision !== "denied")) {
          return res.status(400).json({ error: "each approval needs integrity and decision(approved|denied)" });
        }
        const audited = store.get(d.integrity);
        if (!audited) {
          return res.status(400).json({ error: `audit ${d.name}@${d.version} first (no report for that integrity)` });
        }
        recorded.push(approvals.put({
          name: audited.report.meta.name, version: audited.report.meta.version,
          integrity: d.integrity, decision: d.decision,
          approvedCapabilities: audited.report.capabilities,
          actor: d.actor ?? { type: "human", id: "unknown" },
          reason: d.reason,
          decidedAt: new Date().toISOString(),
        }));
        approvalRequests.clear(d.integrity);
      }
    } catch (err) {
      return sendError(res, err);
    }
    res.json({ approvals: recorded });
  });

  app.get("/-/approvals", (_req, res) => {
    res.json({ approvals: approvals.recent(50) });
  });

  app.delete(/^\/-\/approvals\/(.+)$/, rateGate, authz.requireRole(["operator"]), (req, res) => {
    const integrity = decodeURIComponent(req.params[0] ?? "");
    res.json({ revoked: approvals.remove(integrity) });
  });

  app.post("/-/approval-requests", rateGate, authz.requireRole(["agent"]), (req, res) => {
    const b = req.body as { name?: unknown; version?: unknown; integrity?: unknown; reason?: unknown; requestedBy?: { type?: string; id?: string } };
    if (typeof b?.name !== "string" || typeof b.version !== "string" || typeof b.integrity !== "string" || typeof b.reason !== "string") {
      return res.status(400).json({ error: "need name, version, integrity, reason" });
    }
    const audited = store.get(b.integrity);
    if (!audited) return res.status(400).json({ error: `audit ${b.name}@${b.version} first (no report for that integrity)` });
    const reqByType = b.requestedBy?.type;
    const requestedBy: { type: "human" | "agent"; id: string } =
      reqByType === "human" || reqByType === "agent"
        ? { type: reqByType, id: String(b.requestedBy?.id ?? "unknown") }
        : { type: "agent", id: "mcp" };
    const rec = approvalRequests.record({
      name: audited.report.meta.name, version: audited.report.meta.version, integrity: b.integrity,
      reason: b.reason, requestedBy, capabilities: audited.report.capabilities,
    });
    res.json({ requested: rec });
  });

  app.get("/-/approval-requests", (_req, res) => {
    res.json({ requests: approvalRequests.recent(50) });
  });

  app.post("/-/violations", rateGate, authz.requireRole(["agent"]), (req, res) => {
    const v = req.body as Partial<ViolationInput>;
    if (!v || typeof v.integrity !== "string" || typeof v.name !== "string" || typeof v.version !== "string" ||
        (v.confidence !== "confirmed" && v.confidence !== "suspected") ||
        (v.kind !== "filesystem" && v.kind !== "network" && v.kind !== "process")) {
      return res.status(400).json({ error: "invalid violation: need name, version, integrity, kind, confidence" });
    }
    if (!store.get(v.integrity)) {
      return res.status(400).json({ error: `no audited report for integrity ${v.integrity} — audit before reporting` });
    }
    const rec = violations.record(
      {
        name: v.name, version: v.version, integrity: v.integrity, kind: v.kind,
        target: v.target ?? null, confidence: v.confidence, deniedResource: v.deniedResource ?? null,
        evidence: { exitCode: v.evidence?.exitCode ?? 0, stderrExcerpt: String(v.evidence?.stderrExcerpt ?? "").slice(0, 200) },
      },
      { autoQuarantine: autoQuarantineEnabled && v.confidence === "confirmed" },
    );
    if (rec.quarantined) {
      approvals.remove(v.integrity); // revoke any standing approval for a quarantined build
      console.log(`[violation] quarantined ${v.name}@${v.version} (${rec.kind} → ${rec.target ?? rec.deniedResource})`);
    }
    res.json({ recorded: rec });
  });

  app.get("/-/violations", (_req, res) => {
    res.json({ violations: violations.recent(50) });
  });

  app.delete(/^\/-\/violations\/(.+)$/, rateGate, authz.requireRole(["operator"]), (req, res) => {
    const integrity = decodeURIComponent(req.params[0] ?? "");
    res.json({ cleared: violations.clear(integrity) });
  });

  app.get("/-/private", (_req, res) => {
    res.json({
      claims: enterprisePolicy.privateNamespaces ?? [],
      claimCorpus: { version: claimCorpus.version, hash: claimCorpusHash },
      retractionCorpus: { version: retractionCorpus.version, hash: retractionCorpusHash },
      verifiedClaims: claimCorpus.claims.map((claim) => ({ namespace: claim.namespace, domain: claim.domain, status: claim.status })),
      packages: privateStore.names().map((name) => ({ name, versions: privateStore.versions(name) })),
    });
  });

  // ---- time-locked retraction (ADR-0047) ----
  app.get("/-/retractions", (_req, res) => {
    res.json({
      advisories: [...privateStore.retractionAdvisories(), ...retractionCorpus.advisories],
      retractionCorpus: { version: retractionCorpus.version, hash: retractionCorpusHash },
      windowHits: history ? history.retractionWindowHits() : privateStore.retractionWindowHits(),
      downloadCounting: "Successful native tarball responses count once; with SQLite, repeats for the same package version and npm-session are deduplicated; requests without npm-session count individually.",
    });
  });
  app.post("/-/retractions", rateGate, authz.requireRole(["operator"]), (req, res) => {
    const body = req.body as { name?: unknown; version?: unknown; reason?: unknown };
    let name: string;
    try { name = normalizePackageName(String(body?.name ?? "")); }
    catch (error) { return res.status(400).json({ error: (error as Error).message }); }
    const version = typeof body?.version === "string" ? body.version : "";
    const reasons: RetractionReason[] = ["security", "withdrawn", "broken", "legal"];
    if (!version || !reasons.includes(body?.reason as RetractionReason)) {
      return res.status(400).json({ error: "retraction requires name, version, and reason(security|withdrawn|broken|legal)" });
    }
    if (!isNativeName(name)) return res.status(403).json({ error: "only authoritative native packages can be retracted", package: `${name}@${version}` });
    const stored = privateStore.getVersion(name, version);
    if (!stored) return res.status(404).json({ error: "native package version not found", package: `${name}@${version}` });
    const existing = privateStore.getRetraction(name, version) ?? retractionCorpus.advisories.find((advisory) => advisory.name === name && advisory.version === version);
    if (existing) return res.status(409).json({ error: "package version already retracted", package: `${name}@${version}`, tombstone: existing });

    const nowMs = now();
    const attemptedAt = new Date(nowMs).toISOString();
    const publishedAtMs = Date.parse(stored.publishedAt);
    const ageHours = (nowMs - publishedAtMs) / 3_600_000;
    if (!Number.isFinite(ageHours) || ageHours < 0) {
      return res.status(403).json({ error: "authoritative publish time is invalid; retraction fails closed", code: "retraction-publish-time-invalid" });
    }
    const limits = retractionWindowOf(enterprisePolicy);
    const cumulativeDownloads = history?.downloadCount(name, version) ?? privateStore.downloadCount(name, version);
    const ageExceeded = ageHours >= limits.maxAgeHours;
    const downloadsExceeded = cumulativeDownloads >= limits.maxDownloads;
    const window = {
      publishedAt: stored.publishedAt, attemptedAt, ageHours, cumulativeDownloads,
      maxAgeHours: limits.maxAgeHours, maxDownloads: limits.maxDownloads,
    };
    if (ageExceeded || downloadsExceeded) {
      const hit = { name, version, ageHours, downloads: cumulativeDownloads, ...limits, ageExceeded, downloadsExceeded, attemptedAt };
      if (history) history.recordRetractionWindowHit(hit);
      else privateStore.recordRetractionWindowHit({ ageExceeded, downloadsExceeded });
      const exceeded = [
        ...(ageExceeded ? [{ code: "retraction-age-limit-exceeded", actual: ageHours, limit: limits.maxAgeHours }] : []),
        ...(downloadsExceeded ? [{ code: "retraction-download-limit-exceeded", actual: cumulativeDownloads, limit: limits.maxDownloads }] : []),
      ];
      return res.status(403).json({ error: "retraction window closed", code: "retraction-window-closed", package: `${name}@${version}`, window, exceeded });
    }

    const reason = body.reason as RetractionReason;
    const advisoryId = "SENTINEL-RETRACT-" + createHash("sha256")
      .update(`${name}\u0000${version}\u0000${stored.integrity}\u0000${attemptedAt}\u0000${reason}`)
      .digest("hex").slice(0, 24);
    try {
      const tombstone = privateStore.retract({ name, version, reason, retractedAt: attemptedAt, advisoryId });
      return res.status(201).json({ retracted: true, package: `${name}@${version}`, tombstone, window });
    } catch (error) {
      if (error instanceof PublicationConflictError) return res.status(409).json({ error: error.message });
      return sendError(res, error);
    }
  });

  // ---- publish (PUT /:pkg) — authoritative private registry write path ----
  function requirePublishAuth(req: Request, res: Response, next: () => void): void {
    if (!publishTokenValid(req.headers.authorization, publishTokens)) {
      res.status(401).json({ error: "authentication required to publish" });
      return;
    }
    next();
  }

  const publishAuth = authz.enabled ? authz.requireRole(["publisher"]) : requirePublishAuth;
  app.put(/^\/(.+)$/, publishRateGate, rateGate, publishAuth, jsonPublish, async (req, res) => {
    try {
      let name: string;
      try { name = normalizePackageName(decodeURIComponent(req.params[0] ?? "")); }
      catch (err) { return res.status(400).json({ error: (err as Error).message }); }
      const selectedSource = registrySource(name);
      if (!isNativeSource(selectedSource)) {
        return res.status(403).json({ error: "claim required before publish", package: name });
      }
      const verifiedClaim = selectedSource === "verified-claim" ? claimForPackage(name, claimCorpus) : undefined;
      if (verifiedClaim?.status === "frozen") {
        return res.status(423).json({ error: "verified claim is frozen; publication is disabled", code: "claim-frozen", package: name });
      }
      if (verifiedClaim?.status === "disputed") {
        return res.status(423).json({ error: "verified claim is disputed; publication is disabled while contested", code: "claim-disputed", package: name });
      }
      let parsed;
      try { parsed = parsePublishBody(name, req.body); }
      catch (err) { return res.status(400).json({ error: (err as Error).message, package: name }); }
      if (privateStore.getRetraction(name, parsed.version) ||
          retractionCorpus.advisories.some((advisory) => advisory.name === name && advisory.version === parsed.version)) {
        return res.status(409).json({ error: "version identifier is permanently spent by retraction", package: `${name}@${parsed.version}` });
      }
      const integrity = integrityOf(parsed.tarball);
      if (parsed.declaredIntegrity && parsed.declaredIntegrity !== integrity) {
        return res.status(400).json({ error: "integrity mismatch", package: `${name}@${parsed.version}` });
      }
      const meta = {
        name, version: parsed.version,
        author: null, maintainers: [], license: null,
        hasInstallScripts: false, integrity,
      };
      let audit: Audit;
      try {
        audit = await publishAudit({
          meta, tarball: parsed.tarball, signatures: null, hasProvenance: parsed.attestations !== null,
          attestations: parsed.attestations, signingKeys, trustMaterial: opts.trustMaterial, extractLimits,
          requirePackageManifest: { name, version: parsed.version },
          advisories: [...(advisories ?? []), ...retractionCorpus.advisories], vulnerabilities,
        });
      } catch (err) {
        if ((err as Error).message.startsWith("malformed npm tarball:")) {
          return res.status(400).json({ error: (err as Error).message, package: `${name}@${parsed.version}` });
        }
        throw err; // scanner/internal failures remain fail-closed as 500
      }
      const report = scoreAudit(audit);
      if (verifiedClaim?.trustedPublishers?.length &&
          (audit.meta.provenance !== "verified" || !trustedPublisherAuthorized(verifiedClaim, audit.meta.provenanceIdentity))) {
        return res.status(403).json({
          error: "a matching verified trusted-publisher attestation is required",
          code: "trusted-publisher-required",
          package: `${name}@${parsed.version}`,
          report,
        });
      }
      if (verdictAtOrAbove(report.verdict, publishGateOf(enterprisePolicy))) {
        return res.status(403).json({
          error: "publish blocked by Sentinel policy", package: `${name}@${parsed.version}`,
          report,
        });
      }
      try {
        privateStore.publish({
          name, version: parsed.version, integrity, manifest: parsed.manifest, tarball: parsed.tarball, audit,
          ...(parsed.attestations !== null ? { attestations: parsed.attestations } : {}), actor: "publisher",
          ...(verifiedClaim ? { claimAtPublication: {
            namespace: verifiedClaim.namespace,
            domain: verifiedClaim.domain,
            claimantPublicKey: verifiedClaim.claimantPublicKey,
          } } : {}),
        });
      } catch (err) {
        if (err instanceof PublicationConflictError) {
          return res.status(409).json({ error: "version already published", package: `${name}@${parsed.version}` });
        }
        throw err;
      }
      console.log(`[registry] published ${name}@${parsed.version} from ${selectedSource} (verdict ${report.verdict})`);
      return res.status(201).json({ ok: true, id: name, rev: `1-${integrity.slice(7, 19)}` });
    } catch (err) {
      return sendError(res, err);
    }
  });

  // Keep parser failures on the untrusted publish surface JSON-shaped and
  // fail-closed. This handler must follow the PUT route to receive body-parser errors.
  app.use((err: unknown, req: Request, res: Response, next: (err?: unknown) => void) => {
    const bodyError = err as { type?: string; status?: number; message?: string };
    if (req.method === "PUT" && (bodyError.type === "entity.too.large" || bodyError.status === 413)) {
      res.status(413).json({ error: "publish payload exceeds configured byte limit" });
      return;
    }
    next(err);
  });

  // ---- dashboard ----
  if (opts.publicDir) {
    app.get("/", rateGate, (_req, res) => res.sendFile("index.html", { root: opts.publicDir }));
    app.use("/assets", express.static(opts.publicDir));
  }

  // ---- registry surface ----
  // Everything else is either a tarball fetch or a packument fetch.
  app.get(/.*/, async (req: Request, res: Response) => {
    const path = decodeURIComponent(req.path.replace(/^\//, ""));
    if (!path) return res.status(404).json({ error: "not found" });

    const tar = TARBALL_RE.exec(path);
    if (tar) {
      let pkg: string;
      try { pkg = normalizeRegistryReadName(tar[1] ?? ""); }
      catch (err) { return res.status(400).json({ error: (err as Error).message }); }
      const version = versionFromFilename(pkg, tar[2] ?? "");
      if (!version) return res.status(400).json({ error: "cannot parse version from tarball name" });
      try {
        const priv = isNativeName(pkg);
        const { report, tarball } = await auditVersion(pkg, version);
        const cd = await cooldownFor(pkg, version);
        return gateAndSend(res, pkg, version, report, tarball, priv, cd, priv ? () => {
          const servedAt = new Date(now()).toISOString();
          if (history) history.recordDownload({
            name: pkg, version, integrity: report.meta.integrity ?? integrityOf(tarball),
            ...(req.get("npm-session") ? { npmSession: req.get("npm-session")! } : {}), servedAt,
          });
          else privateStore.recordDownload(pkg, version);
        } : undefined);
      } catch (err) {
        return sendError(res, err);
      }
    }

    // Packument
    try {
      const name = normalizeRegistryReadName(path);
      const base = baseUrlFor(req, publicBaseUrl);
      if (isNativeName(name)) {
        const pm = privateStore.packument(name);
        if (!pm) return res.status(404).json({ error: "native package not found", package: name });
        for (const advisory of retractionCorpus.advisories) {
          if (advisory.name !== name || !pm.versions[advisory.version]) continue;
          if (privateStore.getVersion(name, advisory.version)?.integrity !== advisory.integrity) continue;
          delete pm.versions[advisory.version];
          pm._sentinel ??= { retractions: {} };
          pm._sentinel.retractions[advisory.version] = {
            retractedAt: advisory.retractedAt, reason: advisory.reason, advisoryId: advisory.id,
          };
        }
        const activeVersions = Object.keys(pm.versions).sort(cmpSemver);
        pm["dist-tags"] = activeVersions.length ? { latest: activeVersions.at(-1)! } : {};
        for (const [v, manifest] of Object.entries(pm.versions)) {
          (manifest as { dist?: { tarball?: string } }).dist = { ...(manifest as { dist?: object }).dist, tarball: `${base}/${name}/-/${shortName(name)}-${v}.tgz` };
        }
        res.setHeader("content-type", "application/json");
        res.setHeader("x-sentinel-private", "true");
        return res.json(pm);
      }
      const pm = await upstream.getPackument(name);
      for (const [v, manifest] of Object.entries(pm.doc.versions ?? {})) {
        const fileName = `${shortName(name)}-${v}.tgz`;
        (manifest as { dist: { tarball: string } }).dist.tarball = `${base}/${name}/-/${fileName}`;
      }
      res.setHeader("content-type", "application/json");
      return res.json(pm.doc);
    } catch (err) {
      return sendError(res, err);
    }
  });

  return app;
}

function shortName(pkg: string): string {
  return pkg.includes("/") ? (pkg.split("/").pop() ?? pkg) : pkg;
}

/** Recover the version from `name-1.2.3.tgz`, handling scoped names. */
function versionFromFilename(pkg: string, file: string): string | null {
  const base = shortName(pkg);
  const m = new RegExp(`^${escapeRe(base)}-(.+)\\.tgz$`).exec(file);
  return m ? (m[1] ?? null) : null;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sendError(res: Response, err: unknown): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
  } else {
    res.status(500).json({ error: (err as Error)?.message ?? "internal error" });
  }
}

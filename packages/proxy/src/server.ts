import { Buffer } from "node:buffer";
import express, { type Request, type Response } from "express";
import {
  runAudit,
  score,
  POLICY_SYNTHESIZED_RULE_IDS,
  policyHashOf,
  integrityOf,
  integrityOfAlgo,
  aggregateTree,
  treeGateOf,
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
} from "@sentinel/core";
import { AuditStore } from "./store.js";
import {
  cmpSemver,
  HttpError,
  previousVersion,
  type Upstream,
  type UpstreamPackument,
} from "./upstream.js";
import { ApprovalStore, type Approval } from "./approvals.js";
import { reconcileApproval, type ApprovalState } from "./reconcile.js";
import { PrivatePackageStore } from "./private-store.js";
import { isClaimed, parsePublishBody, publishTokenValid } from "./private.js";
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
  const privateStore = opts.privateStore;
  const publishTokens = opts.publishTokens ?? [];
  const signingKeys = opts.signingKeys ?? NPM_SIGNING_KEYS;
  const advisories = opts.advisories;
  const vulnerabilities = opts.vulnerabilities;
  const publicBaseUrl = opts.publicBaseUrl;
  const maxTreePackages = opts.maxTreePackages ?? 5000;
  const authz = makeAuthz(opts.authPublicKey);
  const app = express();
  app.disable("x-powered-by");
  const jsonSmall = express.json({ limit: "1mb" });
  app.use((req, res, next) => (req.method === "PUT" ? next() : jsonSmall(req, res, next)));
  const jsonPublish = express.json({ limit: "64mb" });

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
    // Claimed names are authoritative private — NEVER consult public upstream.
    if (isClaimed(pkg, enterprisePolicy)) {
      const cachedAudit = privateStore.getAudit(pkg, version);
      const tarball = privateStore.getTarball(pkg, version);
      if (!cachedAudit || !tarball) throw new HttpError(404, `private package not found ${pkg}@${version}`);
      const report = score(cachedAudit, enterprisePolicy, policyHash);
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
    if (cached) return { report: cached.report, tarball };

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
      releaseContext, advisories, vulnerabilities,
    });
    const report = score(audit, enterprisePolicy, policyHash);
    store.put(report);
    return { report, tarball };
  }

  /** Overlay a quarantine on a served report: inject a critical runtime-violation finding + force block. */
  function applyQuarantine(report: AuditReport): AuditReport {
    const rec = violations.get(report.meta.integrity);
    if (!rec?.quarantined) return report;
    const finding = {
      ruleId: "runtime-violation", category: "install-script" as const, severity: "critical" as const,
      message: `runtime violation: ${rec.kind} access to ${rec.target ?? rec.deniedResource ?? "a denied resource"} blocked at install time — build quarantined`,
      onChangedFile: false, evidence: [], weight: 0, waived: false,
    };
    return { ...report, verdict: "block", findings: [finding, ...report.findings] };
  }

  function gateAndSend(res: Response, pkg: string, version: string, report: AuditReport, tarball: Buffer, isPrivate: boolean): Response | void {
    report = applyQuarantine(report);
    const rec = reconcile(report);
    res.setHeader("x-sentinel-score", String(report.score));
    res.setHeader("x-sentinel-verdict", report.verdict);
    res.setHeader("x-sentinel-violations", String(violations.get(report.meta.integrity) ? 1 : 0));
    res.setHeader("x-sentinel-findings", String(report.findings.length));
    res.setHeader("x-sentinel-capabilities", String(report.capabilities.length));
    res.setHeader("x-sentinel-approval", rec.state);
    res.setHeader("x-sentinel-policy", report.policy.version);
    // legacy persisted audits may predate the provenance field
    res.setHeader("x-sentinel-provenance", report.meta.provenance ?? "unknown");
    if (isPrivate) res.setHeader("x-sentinel-private", "true");
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
      res.json(report);
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
      const allVersions = isClaimed(pkg, enterprisePolicy)
        ? privateStore.versions(pkg)
        : Object.keys((await upstream.getPackument(pkg)).versions);
      priors = allVersions.filter((v) => cmpSemver(v, version) < 0).sort(cmpSemver).reverse().slice(0, 10);
    } catch {
      return null;
    }
    for (const v of priors) {
      try {
        const { report } = await auditVersion(pkg, v);
        if (report.verdict === "allow") return { version: v, score: report.score };
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
      const remediation = remediate(report);
      const lastKnownGood = await findLastKnownGood(pkg, version);
      res.json({ report, remediation, lastKnownGood });
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
        to = score({ ...report, findings } as unknown as Audit, candidate);
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
          const report = applyQuarantine(audited);
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
    const result: TreeAuditResult = { aggregate, packages: rows, policyHash };
    res.json(result);
  });

  app.get(/^\/-\/manifest\/(.+)\/([^/]+)$/, async (req, res) => {
    const pkg = decodeURIComponent(req.params[0] ?? "");
    const version = req.params[1] ?? "";
    try {
      const { report } = await auditVersion(pkg, version);
      const rec = reconcile(report);
      res.json({
        meta: report.meta, score: report.score, verdict: report.verdict,
        findings: report.findings, capabilities: report.capabilities,
        capabilityDelta: report.capabilityDelta,
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
    const rec = violations.record({
      name: v.name, version: v.version, integrity: v.integrity, kind: v.kind,
      target: v.target ?? null, confidence: v.confidence, deniedResource: v.deniedResource ?? null,
      evidence: { exitCode: v.evidence?.exitCode ?? 0, stderrExcerpt: String(v.evidence?.stderrExcerpt ?? "").slice(0, 200) },
    });
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
      packages: privateStore.names().map((name) => ({ name, versions: privateStore.versions(name) })),
    });
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
  app.put(/^\/(.+)$/, rateGate, publishAuth, jsonPublish, async (req, res) => {
    try {
      const name = decodeURIComponent(req.params[0] ?? "");
      if (!isClaimed(name, enterprisePolicy)) {
        return res.status(403).json({ error: "not a private namespace", package: name });
      }
      const parsed = parsePublishBody(name, req.body);
      const integrity = integrityOf(parsed.tarball);
      if (parsed.declaredIntegrity && parsed.declaredIntegrity !== integrity) {
        return res.status(400).json({ error: "integrity mismatch", package: `${name}@${parsed.version}` });
      }
      if (privateStore.getVersion(name, parsed.version)) {
        return res.status(409).json({ error: "version already published", package: `${name}@${parsed.version}` });
      }
      const meta = {
        name, version: parsed.version,
        author: null, maintainers: [], license: null,
        hasInstallScripts: false, integrity,
      };
      const audit = await runAudit({ meta, tarball: parsed.tarball, signatures: null, hasProvenance: false, attestations: null, signingKeys });
      const report = score(audit, enterprisePolicy, policyHash);
      if (report.verdict === "block") {
        return res.status(403).json({
          error: "publish blocked by Sentinel policy", package: `${name}@${parsed.version}`,
          verdict: report.verdict,
          findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
        });
      }
      privateStore.put({ name, version: parsed.version, integrity, manifest: parsed.manifest, tarball: parsed.tarball, audit, actor: "publish-token" });
      console.log(`[private] published ${name}@${parsed.version} (verdict ${report.verdict})`);
      return res.status(201).json({ ok: true, id: name, rev: `1-${integrity.slice(7, 19)}` });
    } catch (err) {
      return sendError(res, err);
    }
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
      const pkg = tar[1] ?? "";
      const version = versionFromFilename(pkg, tar[2] ?? "");
      if (!version) return res.status(400).json({ error: "cannot parse version from tarball name" });
      try {
        const priv = isClaimed(pkg, enterprisePolicy);
        const { report, tarball } = await auditVersion(pkg, version);
        return gateAndSend(res, pkg, version, report, tarball, priv);
      } catch (err) {
        return sendError(res, err);
      }
    }

    // Packument
    try {
      const base = baseUrlFor(req, publicBaseUrl);
      if (isClaimed(path, enterprisePolicy)) {
        const pm = privateStore.packument(path);
        if (!pm) return res.status(404).json({ error: "private package not found", package: path });
        for (const [v, manifest] of Object.entries(pm.versions)) {
          (manifest as { dist?: { tarball?: string } }).dist = { ...(manifest as { dist?: object }).dist, tarball: `${base}/${path}/-/${shortName(path)}-${v}.tgz` };
        }
        res.setHeader("content-type", "application/json");
        res.setHeader("x-sentinel-private", "true");
        return res.json(pm);
      }
      const pm = await upstream.getPackument(path);
      for (const [v, manifest] of Object.entries(pm.doc.versions ?? {})) {
        const fileName = `${shortName(path)}-${v}.tgz`;
        (manifest as { dist: { tarball: string } }).dist.tarball = `${base}/${path}/-/${fileName}`;
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

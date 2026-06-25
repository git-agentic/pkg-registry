import { Buffer } from "node:buffer";
import express, { type Request, type Response } from "express";
import {
  runAudit,
  score,
  policyHashOf,
  integrityOf,
  type AuditReport,
  type EnterprisePolicy,
  type PackageMeta,
} from "@sentinel/core";
import { AuditStore } from "./store.js";
import {
  cmpSemver,
  HttpError,
  previousVersion,
  type Upstream,
} from "./upstream.js";
import { ApprovalStore, type Approval } from "./approvals.js";
import { reconcileApproval, type ApprovalState } from "./reconcile.js";
import { PrivatePackageStore } from "./private-store.js";
import { isClaimed, parsePublishBody, publishTokenValid } from "./private.js";

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
}

const TARBALL_RE = /^(.+)\/-\/([^/]+\.tgz)$/;

export function createServer(opts: ServerOptions) {
  const { upstream, store, approvals } = opts;
  const enterprisePolicy = opts.enterprisePolicy;
  const policyHash = opts.policyHash ?? policyHashOf(enterprisePolicy);
  const policy: ProxyPolicy = opts.policy ?? "observe";
  const privateStore = opts.privateStore;
  const publishTokens = opts.publishTokens ?? [];
  const app = express();
  app.disable("x-powered-by");
  const jsonSmall = express.json({ limit: "1mb" });
  app.use((req, res, next) => (req.method === "PUT" ? next() : jsonSmall(req, res, next)));
  const jsonPublish = express.json({ limit: "64mb" });

  /** Audit a specific version, using the verdict cache (integrity-keyed). */
  async function auditVersion(
    pkg: string,
    version: string,
    providedTarball?: Buffer,
  ): Promise<{ report: AuditReport; tarball: Buffer }> {
    const pm = await upstream.getPackument(pkg);
    const vmeta = pm.versions[version];
    if (!vmeta) throw new HttpError(404, `unknown version ${pkg}@${version}`);

    const tarball = providedTarball ?? (await upstream.getTarball(pkg, version));
    const integrity = vmeta.integrity ?? integrityOf(tarball);

    const cached = store.get(integrity);
    if (cached) return { report: cached.report, tarball };

    const prev = previousVersion(Object.keys(pm.versions), version);
    const baselineTarball = prev ? await upstream.getTarball(pkg, prev) : undefined;

    const meta: Omit<PackageMeta, "unpackedSize" | "fileCount"> = {
      name: pkg,
      version,
      author: vmeta.author,
      maintainers: vmeta.maintainers,
      license: vmeta.license,
      hasInstallScripts: vmeta.hasInstallScripts,
      signatureStatus: vmeta.signatureStatus,
      integrity,
    };

    const audit = await runAudit({ meta, tarball, baselineTarball });
    const report = score(audit, enterprisePolicy, policyHash);
    store.put(report);
    return { report, tarball };
  }

  function gateAndSend(res: Response, pkg: string, version: string, report: AuditReport, tarball: Buffer, isPrivate: boolean): Response | void {
    const rec = reconcile(report);
    res.setHeader("x-sentinel-score", String(report.score));
    res.setHeader("x-sentinel-verdict", report.verdict);
    res.setHeader("x-sentinel-findings", String(report.findings.length));
    res.setHeader("x-sentinel-capabilities", String(report.capabilities.length));
    res.setHeader("x-sentinel-approval", rec.state);
    res.setHeader("x-sentinel-policy", report.policy.version);
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

  app.get("/-/audits", (_req, res) => {
    res.json({ stats: store.stats(), audits: store.recent(50).map((s) => s.report) });
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

  app.post("/-/approvals", (req, res) => {
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
      }
    } catch (err) {
      return sendError(res, err);
    }
    res.json({ approvals: recorded });
  });

  app.get("/-/approvals", (_req, res) => {
    res.json({ approvals: approvals.recent(50) });
  });

  app.delete(/^\/-\/approvals\/(.+)$/, (req, res) => {
    const integrity = decodeURIComponent(req.params[0] ?? "");
    res.json({ revoked: approvals.remove(integrity) });
  });

  // ---- publish (PUT /:pkg) — authoritative private registry write path ----
  function requirePublishAuth(req: Request, res: Response, next: () => void): void {
    if (!publishTokenValid(req.headers.authorization, publishTokens)) {
      res.status(401).json({ error: "authentication required to publish" });
      return;
    }
    next();
  }

  app.put(/^\/(.+)$/, requirePublishAuth, jsonPublish, async (req, res) => {
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
        hasInstallScripts: false, signatureStatus: "unknown" as const, integrity,
      };
      const audit = await runAudit({ meta, tarball: parsed.tarball });
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
    app.get("/", (_req, res) => res.sendFile("index.html", { root: opts.publicDir }));
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
        if (isClaimed(pkg, enterprisePolicy)) {
          const audit = privateStore.getAudit(pkg, version);
          const tarball = privateStore.getTarball(pkg, version);
          if (!audit || !tarball) return res.status(404).json({ error: "private package not found", package: `${pkg}@${version}` });
          const report = score(audit, enterprisePolicy, policyHash);
          return gateAndSend(res, pkg, version, report, tarball, true);
        }
        const { report, tarball } = await auditVersion(pkg, version);
        return gateAndSend(res, pkg, version, report, tarball, false);
      } catch (err) {
        return sendError(res, err);
      }
    }

    // Packument
    try {
      const base = `${req.protocol}://${req.get("host")}`;
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

import { Buffer } from "node:buffer";
import express, { type Request, type Response } from "express";
import {
  auditTarball,
  integrityOf,
  type AuditReport,
  type PackageMeta,
} from "@sentinel/core";
import { AuditStore } from "./store.js";
import {
  HttpError,
  previousVersion,
  type Upstream,
} from "./upstream.js";

export type ProxyPolicy = "observe" | "block";

export interface ServerOptions {
  upstream: Upstream;
  store: AuditStore;
  /** `observe` always serves (audits + headers only); `block` 403s on a block verdict. */
  policy?: ProxyPolicy;
  /** Directory containing the dashboard `index.html`. */
  publicDir?: string;
}

const TARBALL_RE = /^(.+)\/-\/([^/]+\.tgz)$/;

export function createServer(opts: ServerOptions) {
  const { upstream, store } = opts;
  const policy: ProxyPolicy = opts.policy ?? "observe";
  const app = express();
  app.disable("x-powered-by");

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

    const report = await auditTarball({ meta, tarball, baselineTarball });
    store.put(report);
    return { report, tarball };
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
        const { report, tarball } = await auditVersion(pkg, version);
        res.setHeader("x-sentinel-score", String(report.score));
        res.setHeader("x-sentinel-verdict", report.verdict);
        res.setHeader("x-sentinel-findings", String(report.findings.length));
        if (policy === "block" && report.verdict === "block") {
          return res.status(403).json({
            error: "blocked by Sentinel policy",
            package: `${pkg}@${version}`,
            score: report.score,
            verdict: report.verdict,
            findings: report.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
          });
        }
        res.setHeader("content-type", "application/octet-stream");
        return res.send(tarball);
      } catch (err) {
        return sendError(res, err);
      }
    }

    // Packument: pass the upstream doc through, rewriting only the tarball URLs.
    try {
      const base = `${req.protocol}://${req.get("host")}`;
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

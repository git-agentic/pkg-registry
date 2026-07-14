import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import express, { type Request, type Response } from "express";
import { rateLimit } from "express-rate-limit";
import { ClaimSteward, type ClaimApplicationInput, type TxtResolver } from "./steward.js";
import type { RetractionAdvisory } from "@agentic-sentinel/core";

export interface StewardServerOptions {
  steward: ClaimSteward;
  token: string;
  resolveTxt: TxtResolver;
  privateKeyPem: string;
  releaseDir?: string;
  /** Mandatory control-plane limiter. Undefined ⇒ 120 requests per source per minute. */
  controlRateLimit?: { limit: number; windowMs: number };
}

function digest(value: string): Buffer { return createHash("sha256").update(value).digest(); }

function bearerValid(header: string | undefined, expected: string): boolean {
  const match = /^Bearer\s+(\S.*)$/i.exec(header ?? "");
  return Boolean(match && timingSafeEqual(digest((match![1] ?? "").trim()), digest(expected)));
}

function sendError(res: Response, error: unknown): void {
  res.status(400).json({ error: (error as Error).message });
}

/** Authenticated steward control plane. Every mutation is operator-token gated. */
export function createStewardServer(options: StewardServerOptions) {
  if (!options.token) throw new Error("steward token must be configured");
  const app = express();
  app.disable("x-powered-by");
  app.use(rateLimit({
    windowMs: options.controlRateLimit?.windowMs ?? 60_000,
    limit: options.controlRateLimit?.limit ?? 120,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "steward rate limit exceeded — retry later" },
  }));
  app.use(express.json({ limit: "1mb" }));
  app.use((req, res, next) => {
    if (!bearerValid(req.headers.authorization, options.token)) return res.status(401).json({ error: "steward authentication required" });
    next();
  });

  app.post("/-/claims/challenges", async (req: Request, res: Response) => {
    try { res.status(201).json(await options.steward.issueChallenge(req.body as ClaimApplicationInput)); }
    catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/challenges/:id/verify", async (req, res) => {
    try { res.json({ verified: await options.steward.verifyChallenge(req.params.id, options.resolveTxt) }); }
    catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/challenges/:id/approve", (req, res) => {
    try { options.steward.approve(req.params.id, req.body as { evidenceRef?: string }); res.json({ approved: true }); }
    catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/transfers", (req, res) => {
    try {
      const body = req.body as { namespace: string; targetChallengeId: string; oldClaimantSignature: string };
      options.steward.requestTransfer(body.namespace, body.targetChallengeId, body.oldClaimantSignature);
      res.status(202).json({ pending: true });
    } catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/disputes", (req, res) => {
    try { options.steward.contest((req.body as { namespace: string }).namespace); res.status(202).json({ frozen: true }); }
    catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/dispute-rulings", (req, res) => {
    try {
      const body = req.body as { namespace: string; targetChallengeId: string; evidenceRef: string };
      options.steward.ruleDispute(body.namespace, body.targetChallengeId, body.evidenceRef);
      res.status(202).json({ pending: true });
    } catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/renewals", (req, res) => {
    try {
      const body = req.body as { namespace: string; challengeId: string };
      options.steward.renew(body.namespace, body.challengeId);
      res.json({ renewed: true });
    } catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/freeze-expired", (_req, res) => {
    options.steward.freezeExpiredClaims();
    res.json({ frozen: true });
  });
  app.post("/-/claims/domain-change-freezes", (req, res) => {
    try {
      const body = req.body as { namespace: string; evidenceRef: string };
      options.steward.freezeForDomainChange(body.namespace, body.evidenceRef);
      res.json({ frozen: true });
    } catch (error) { sendError(res, error); }
  });
  app.post("/-/retractions", (req, res) => {
    try { options.steward.recordRetraction(req.body as RetractionAdvisory); res.status(202).json({ queued: true }); }
    catch (error) { sendError(res, error); }
  });
  app.post("/-/claims/releases", (req, res) => {
    try {
      const version = (req.body as { version?: unknown }).version;
      if (typeof version !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(version)) throw new Error("release version is required and must be path-safe");
      const release = options.steward.release(version, options.privateKeyPem);
      let releasePath: string | undefined;
      if (options.releaseDir) {
        mkdirSync(options.releaseDir, { recursive: true });
        const staging = mkdtempSync(join(options.releaseDir, ".release-"));
        // The signed corpus carries the operator-supplied version. Filesystem
        // selection is intentionally independent of request data.
        const finalDir = join(options.releaseDir, randomBytes(32).toString("hex"));
        try {
          writeFileSync(join(staging, "claims.json"), release.raw, { flag: "wx" });
          writeFileSync(join(staging, "claims.json.sig"), release.signature!, { flag: "wx" });
          writeFileSync(join(staging, "advisories.json"), release.retractionRaw, { flag: "wx" });
          writeFileSync(join(staging, "advisories.json.sig"), release.retractionSignature!, { flag: "wx" });
          renameSync(staging, finalDir);
          releasePath = finalDir;
        } catch (error) {
          rmSync(staging, { recursive: true, force: true });
          throw error;
        }
      }
      res.json({ version, claims: release.corpus.claims.length, pendingClaims: release.corpus.pendingClaims?.length ?? 0,
        retractions: release.retractionCorpus.advisories.length, corpus: release.corpus, signature: release.signature,
        retractionCorpus: release.retractionCorpus, retractionSignature: release.retractionSignature, releasePath });
    } catch (error) { sendError(res, error); }
  });
  return app;
}

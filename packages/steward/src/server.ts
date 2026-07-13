import { createHash, timingSafeEqual } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import express, { type Request, type Response } from "express";
import { ClaimSteward, type ClaimApplicationInput, type TxtResolver } from "./steward.js";

export interface StewardServerOptions {
  steward: ClaimSteward;
  token: string;
  resolveTxt: TxtResolver;
  privateKeyPem: string;
  releaseDir?: string;
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
  app.use(express.json({ limit: "1mb" }));
  app.use((req, res, next) => {
    if (!bearerValid(req.headers.authorization, options.token)) return res.status(401).json({ error: "steward authentication required" });
    next();
  });

  app.post("/-/claims/challenges", (req: Request, res: Response) => {
    try { res.status(201).json(options.steward.issueChallenge(req.body as ClaimApplicationInput)); }
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
  app.post("/-/claims/releases", (req, res) => {
    try {
      const version = (req.body as { version?: unknown }).version;
      if (typeof version !== "string" || !version) throw new Error("release version is required");
      const release = options.steward.release(version, options.privateKeyPem);
      if (options.releaseDir) {
        mkdirSync(options.releaseDir, { recursive: true });
        const corpusPath = join(options.releaseDir, "claims.json");
        const sigPath = `${corpusPath}.sig`;
        const nonce = `${process.pid}-${Date.now()}`;
        writeFileSync(`${corpusPath}.${nonce}.tmp`, release.raw);
        writeFileSync(`${sigPath}.${nonce}.tmp`, release.signature!);
        renameSync(`${corpusPath}.${nonce}.tmp`, corpusPath);
        renameSync(`${sigPath}.${nonce}.tmp`, sigPath);
      }
      res.json({ version, claims: release.corpus.claims.length, pendingClaims: release.corpus.pendingClaims?.length ?? 0,
        corpus: release.corpus, signature: release.signature });
    } catch (error) { sendError(res, error); }
  });
  return app;
}

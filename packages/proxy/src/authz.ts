import type { Request, Response, RequestHandler } from "express";
import { verifyToken, type Role } from "@git-agentic/sentinel-core";

/** Build the authz layer. `publicKeyPem` undefined ⇒ auth disabled (pass-through). */
export function makeAuthz(publicKeyPem: string | undefined): { enabled: boolean; requireRole(roles: Role[]): RequestHandler } {
  const enabled = Boolean(publicKeyPem);

  function requireRole(roles: Role[]): RequestHandler {
    if (!enabled) return (_req, _res, next) => next();
    return (req: Request, res: Response, next: () => void) => {
      const header = req.headers.authorization;
      if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "authentication required (Bearer token)" });
      }
      const result = verifyToken(header.slice("Bearer ".length).trim(), publicKeyPem!);
      if (!result.ok) {
        return res.status(401).json({ error: `invalid token: ${result.reason}` });
      }
      if (!roles.includes(result.role)) {
        return res.status(403).json({ error: `role ${result.role} not permitted (need ${roles.join(" or ")})` });
      }
      next();
    };
  }

  return { enabled, requireRole };
}

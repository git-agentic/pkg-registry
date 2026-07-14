import { readFileSync } from "node:fs";
import { z } from "zod";
import { parseLockfile } from "@git-agentic/sentinel-core";
import type { ProxyClient } from "./client.js";
import { summarizeAudit } from "./format.js";

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, z.ZodType>;
  handler(args: Record<string, unknown>, client: ProxyClient): Promise<{ text: string; structured: unknown }>;
}

async function isQuarantined(client: ProxyClient, integrity: string | null): Promise<boolean> {
  if (!integrity) return false;
  const v = await client.violations();
  return v.some((x) => x.integrity === integrity && x.quarantined);
}

export const TOOLS: ToolDef[] = [
  {
    name: "sentinel_audit",
    description: "Audit an npm package version before installing: verdict, score, findings, capabilities, signature/provenance status, and whether it is quarantined by a runtime violation.",
    inputSchema: { package: z.string(), version: z.string().optional() },
    async handler(args, client) {
      const rep = await client.audit(args.package as string, args.version as string | undefined);
      const quarantined = await isQuarantined(client, rep.meta.integrity);
      return {
        text: summarizeAudit(rep, quarantined),
        structured: {
          package: rep.meta.name, version: rep.meta.version, verdict: rep.verdict, score: rep.score,
          quarantined, signature: rep.meta.signature, provenance: rep.meta.provenance,
          hasInstallScripts: rep.meta.hasInstallScripts,
          capabilities: rep.capabilities, findings: rep.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, message: f.message })),
        },
      };
    },
  },
  {
    name: "sentinel_audit_tree",
    description: "Audit every package in an npm package-lock.json and return the aggregate verdict, whether the tree is gated, and the worst offenders.",
    inputSchema: { lockfile: z.string() },
    async handler(args, client) {
      const coords = parseLockfile(readFileSync(args.lockfile as string, "utf8"));
      const result = await client.auditTree(coords.map((c) => ({ name: c.name, version: c.version })));
      return {
        text: `tree: ${result.aggregate.verdict.toUpperCase()}${result.aggregate.gated ? " (GATED)" : ""} · ` +
          Object.entries(result.aggregate.counts).map(([k, v]) => `${v} ${k}`).join(" · "),
        structured: {
          verdict: result.aggregate.verdict, gated: result.aggregate.gated,
          counts: result.aggregate.counts, packages: result.packages,
        },
      };
    },
  },
  {
    name: "sentinel_capabilities",
    description: "Show a package's capability manifest (network/filesystem/process/env/native), the delta vs the prior version, and its approval state.",
    inputSchema: { package: z.string(), version: z.string().optional() },
    async handler(args, client) {
      const m = await client.manifest(args.package as string, args.version as string | undefined);
      return {
        text: `${m.meta.name}@${m.meta.version} — ${m.capabilities.length} capabilities · approval: ${m.approvalState}` +
          (m.approvalRequired.length ? ` · ${m.approvalRequired.length} need approval` : ""),
        structured: { capabilities: m.capabilities, capabilityDelta: m.capabilityDelta, approvalState: m.approvalState, approvalRequired: m.approvalRequired },
      };
    },
  },
  {
    name: "sentinel_check_provenance",
    description: "Report a package's build-provenance status (verified/invalid/absent/unknown) and, when verified, the source repo, workflow, builder, and commit.",
    inputSchema: { package: z.string(), version: z.string().optional() },
    async handler(args, client) {
      const rep = await client.audit(args.package as string, args.version as string | undefined);
      const id = rep.meta.provenanceIdentity ?? null;
      return {
        text: `${rep.meta.name}@${rep.meta.version} — provenance ${rep.meta.provenance}` +
          (id ? `\nbuilt by ${id.builder ?? "?"} from ${id.sourceRepository ?? "?"}${id.ref ? `@${id.ref}` : ""}${id.commit ? ` (${id.commit.slice(0, 7)})` : ""}` : ""),
        structured: { provenance: rep.meta.provenance, provenanceIdentity: id, signature: rep.meta.signature },
      };
    },
  },
  {
    name: "sentinel_list_violations",
    description: "List runtime violations the sandbox has recorded, and which package builds are quarantined.",
    inputSchema: { package: z.string().optional() },
    async handler(args, client) {
      let violations = await client.violations();
      if (args.package) violations = violations.filter((v) => v.name === args.package);
      return {
        text: violations.length ? violations.map((v) => `${v.quarantined ? "QUARANTINED" : v.confidence} ${v.name}@${v.version} ${v.kind} → ${v.target ?? "?"}`).join("\n") : "no runtime violations recorded",
        structured: { violations },
      };
    },
  },
  {
    name: "sentinel_explain",
    description: "Explain a package version's verdict and how to remediate it: per-finding actions, a suggested known-good earlier version, and a ready approval-request payload.",
    inputSchema: { package: z.string(), version: z.string() },
    async handler(args, client) {
      const result = await client.explain(args.package as string, args.version as string);
      const lines = [result.remediation.guidance, ...result.remediation.items.map((i) => `- ${i.ruleId}: ${i.action}`)];
      if (result.lastKnownGood) lines.push(`Suggested safe version: ${result.lastKnownGood.version}`);
      return { text: lines.join("\n"), structured: result };
    },
  },
  {
    name: "sentinel_request_approval",
    description: "Request that a human approve installing a package whose capabilities need approval. Records a pending request; it does NOT grant approval.",
    inputSchema: { package: z.string(), version: z.string().optional(), reason: z.string() },
    async handler(args, client) {
      const rep = await client.audit(args.package as string, args.version as string | undefined);
      await client.approvalRequest({ name: rep.meta.name, version: rep.meta.version, integrity: rep.meta.integrity!, reason: args.reason as string });
      return {
        text: `Recorded an approval request for ${rep.meta.name}@${rep.meta.version} (current verdict: ${rep.verdict}). A human must approve it in the Sentinel dashboard before install proceeds.`,
        structured: { requested: true, package: rep.meta.name, version: rep.meta.version, verdict: rep.verdict },
      };
    },
  },
];

import { writeFileSync } from "node:fs";
import type { ClaimCorpus, EnterprisePolicy } from "@git-agentic/sentinel-core";
import type { PrivatePackageStore } from "./private-store.js";
import { EMPTY_CLAIM_CORPUS, source } from "./resolution.js";
import type { RegistryMode } from "./server.js";

export interface RevertManifest {
  schema: 1;
  generatedAt: string;
  registryMode: "off";
  retainedNativeNames: string[];
  resolutionFlips: { name: string; selector: "package" | "namespace"; exceptPolicyPatterns?: string[];
    from: "verified-claim"; to: "public-mirror"; risk: string }[];
  safePath: string;
}

/** Whether an anchored `*` glob covers every possible package beginning with
 * prefix. This is the symbolic containment check needed for a scoped claim;
 * sampling one made-up package can be defeated by an exact policy exception. */
function globCoversPrefix(pattern: string, prefix: string): boolean {
  const closure = (input: Set<number>) => {
    const states = new Set(input);
    for (const index of states) if (pattern[index] === "*") states.add(index + 1);
    return states;
  };
  let states = closure(new Set([0]));
  for (const character of prefix) {
    const next = new Set<number>();
    for (const index of states) {
      if (pattern[index] === "*") next.add(index);
      else if (pattern[index] === character) next.add(index + 1);
    }
    states = closure(next);
  }
  return [...states].some((index) => pattern.slice(index).includes("*") && /^\**$/.test(pattern.slice(index)));
}

export function configureRegistryMode(input: {
  rawMode?: string;
  acknowledged?: string;
  manifestPath?: string;
  privateStore: PrivatePackageStore;
  policy: EnterprisePolicy;
  claimCorpus: ClaimCorpus;
  now?: () => number;
}): { mode: RegistryMode; manifest?: RevertManifest } {
  const raw = input.rawMode ?? "on";
  if (raw !== "on" && raw !== "off") throw new Error("SENTINEL_REGISTRY_MODE must be exactly 'on' or 'off'");
  if (raw === "on") return { mode: "on" };
  const names = input.privateStore.names().sort();
  if (names.length && input.acknowledged !== "1") {
    throw new Error("SENTINEL_REGISTRY_MODE=off with native content requires SENTINEL_REGISTRY_MODE_OFF_ACK=1");
  }
  const exactCandidates = new Set([...names, ...input.claimCorpus.claims.filter((claim) => !claim.namespace.endsWith("/*")).map((claim) => claim.namespace)]);
  const resolutionFlips: RevertManifest["resolutionFlips"] = [...exactCandidates].sort().flatMap((name) =>
    source(name, input.policy, input.claimCorpus) === "verified-claim" && source(name, input.policy, EMPTY_CLAIM_CORPUS) === "public-mirror"
      ? [{ name, selector: "package" as const, from: "verified-claim" as const, to: "public-mirror" as const,
          risk: "dependency-confusion resurrection: public npm becomes authoritative for this name" }]
      : []);
  for (const claim of input.claimCorpus.claims.filter((candidate) => candidate.namespace.endsWith("/*"))) {
    const policyPatterns = input.policy.privateNamespaces ?? [];
    if (!policyPatterns.some((pattern) => globCoversPrefix(pattern, claim.namespace.slice(0, -1)))) {
      resolutionFlips.push({ name: claim.namespace, selector: "namespace", exceptPolicyPatterns: [...policyPatterns],
        from: "verified-claim", to: "public-mirror",
        risk: "dependency-confusion resurrection: public npm becomes authoritative for names in this namespace except those retained by signed policy" });
    }
  }
  const manifest: RevertManifest = {
    schema: 1,
    generatedAt: new Date((input.now ?? Date.now)()).toISOString(),
    registryMode: "off",
    retainedNativeNames: names,
    resolutionFlips,
    safePath: "Before disabling registry mode, migrate every flipped name into the signed policy privateNamespaces list.",
  };
  if (input.manifestPath) writeFileSync(input.manifestPath, JSON.stringify(manifest, null, 2));
  return { mode: "off", manifest };
}

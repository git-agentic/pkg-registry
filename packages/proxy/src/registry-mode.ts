import { writeFileSync } from "node:fs";
import type { ClaimCorpus, EnterprisePolicy } from "@sentinel/core";
import type { PrivatePackageStore } from "./private-store.js";
import { EMPTY_CLAIM_CORPUS, source } from "./resolution.js";
import type { RegistryMode } from "./server.js";

export interface RevertManifest {
  schema: 1;
  generatedAt: string;
  registryMode: "off";
  retainedNativeNames: string[];
  resolutionFlips: { name: string; from: "verified-claim"; to: "public-mirror"; risk: string }[];
  safePath: string;
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
  const resolutionFlips = names.flatMap((name) =>
    source(name, input.policy, input.claimCorpus) === "verified-claim" &&
    source(name, input.policy, EMPTY_CLAIM_CORPUS) === "public-mirror"
      ? [{ name, from: "verified-claim" as const, to: "public-mirror" as const,
          risk: "dependency-confusion resurrection: public npm becomes authoritative for this name" }]
      : []);
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

#!/usr/bin/env node
import { readFileSync, realpathSync } from "node:fs";
import { resolveTxt } from "node:dns/promises";
import { pathToFileURL } from "node:url";
import { ClaimSteward, type UpstreamClaimEvidence } from "./steward.js";
import { createStewardServer } from "./server.js";

export { ClaimSteward, corroboratesClaimDomain, signTransferRequest, transferRequestBytes, type ClaimApplicationInput, type ClaimChallenge, type GrandfatherTier, type TxtResolver, type UpstreamClaimEvidence, type UpstreamClaimLookup } from "./steward.js";
export { createStewardServer, type StewardServerOptions } from "./server.js";

function main(): void {
  const token = process.env.SENTINEL_STEWARD_TOKEN;
  const keyPath = process.env.SENTINEL_CLAIM_CORPUS_PRIVATE_KEY;
  const releaseDir = process.env.SENTINEL_CLAIM_CORPUS_RELEASE_DIR;
  const stateFile = process.env.SENTINEL_STEWARD_STATE;
  if (!token || !keyPath || !releaseDir || !stateFile) {
    console.error("FATAL: SENTINEL_STEWARD_TOKEN, SENTINEL_STEWARD_STATE, SENTINEL_CLAIM_CORPUS_PRIVATE_KEY, and SENTINEL_CLAIM_CORPUS_RELEASE_DIR are required");
    process.exit(1);
  }
  let privateKeyPem: string;
  try { privateKeyPem = readFileSync(keyPath, "utf8"); }
  catch (error) { console.error(`FATAL: cannot read claim-corpus private key: ${(error as Error).message}`); process.exit(1); }
  const port = Number(process.env.SENTINEL_STEWARD_PORT ?? "4874");
  if (!Number.isInteger(port) || port < 0 || port > 65535) { console.error("FATAL: SENTINEL_STEWARD_PORT must be an integer in [0, 65535]"); process.exit(1); }
  const registry = process.env.SENTINEL_STEWARD_REGISTRY ?? "https://registry.npmjs.org";
  try {
    const parsed = new URL(registry);
    if (!/^https?:$/.test(parsed.protocol) || parsed.username || parsed.password) throw new Error("invalid registry URL");
  } catch { console.error("FATAL: SENTINEL_STEWARD_REGISTRY must be a bare http(s) URL"); process.exit(1); }
  const lookupUpstream = async (namespace: string): Promise<UpstreamClaimEvidence> => {
    // A scope claim can contain many existing packages; without a separately
    // corroborated exact package it is contested, never presumed free.
    if (namespace.endsWith("/*")) return { kind: "active", packument: {} };
    const url = `${registry.replace(/\/$/, "")}/${encodeURIComponent(namespace).replaceAll("%40", "@")}`;
    const response = await fetch(url);
    if (response.status === 404) return { kind: "absent" };
    if (!response.ok) throw new Error(`upstream packument lookup failed: ${response.status}`);
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (declared > 8 * 1024 * 1024) throw new Error("upstream packument exceeds 8 MiB");
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > 8 * 1024 * 1024) throw new Error("upstream packument exceeds 8 MiB");
    return { kind: "active", packument: JSON.parse(Buffer.from(bytes).toString("utf8")) };
  };
  let steward: ClaimSteward;
  try { steward = new ClaimSteward({ stateFile, lookupUpstream }); }
  catch (error) { console.error(`FATAL: cannot load steward state: ${(error as Error).message}`); process.exit(1); }
  const app = createStewardServer({ steward, token, resolveTxt, privateKeyPem, releaseDir });
  app.listen(port, () => console.log(`Sentinel claim steward listening on http://localhost:${port}`));
}

function isEntrypoint(): boolean {
  const arg = process.argv[1];
  if (!arg) return false;
  try { return import.meta.url === pathToFileURL(realpathSync(arg)).href; } catch { return false; }
}
if (isEntrypoint()) main();

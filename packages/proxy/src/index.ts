#!/usr/bin/env node
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, type ProxyPolicy } from "./server.js";
import { AuditStore } from "./store.js";
import { LocalFixtureUpstream, NpmUpstream, type Upstream } from "./upstream.js";

export { createServer } from "./server.js";
export { AuditStore } from "./store.js";
export * from "./upstream.js";

function env(name: string, fallback: string): string {
  return process.env[name] ?? fallback;
}

function buildUpstream(): Upstream {
  const mode = env("SENTINEL_UPSTREAM", "npm");
  if (mode === "fixtures" || mode.startsWith("fixtures:")) {
    const dir = mode.includes(":")
      ? resolve(mode.split(":")[1] ?? "")
      : resolve(env("SENTINEL_FIXTURES", "fixtures"));
    return new LocalFixtureUpstream(dir);
  }
  return new NpmUpstream(env("SENTINEL_REGISTRY", "https://registry.npmjs.org"));
}

function main(): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const port = Number(env("SENTINEL_PORT", "4873"));
  const policy = env("SENTINEL_POLICY", "observe") as ProxyPolicy;
  const upstream = buildUpstream();
  const store = new AuditStore(process.env.SENTINEL_STORE);
  // dist/index.js -> ../public ; src is run via tsx with the same relative layout.
  const publicDir = env("SENTINEL_PUBLIC", join(here, "..", "public"));

  const app = createServer({ upstream, store, policy, publicDir });
  app.listen(port, () => {
    console.log(`Sentinel proxy listening on http://localhost:${port}`);
    console.log(`  upstream : ${upstream.name}`);
    console.log(`  policy   : ${policy}  (observe = audit+serve, block = 403 on block verdict)`);
    console.log(`  dashboard: http://localhost:${port}/`);
    console.log(`\nPoint npm at it:  npm install --registry http://localhost:${port}`);
  });
}

main();

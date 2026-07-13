#!/usr/bin/env node
import { Command } from "commander";
import { exportNativeStore } from "./registry-export.js";

const program = new Command().name("sentinel-registry").description("Sentinel registry migration utilities");

program.command("export")
  .requiredOption("--store <dir>", "SENTINEL_PRIVATE_STORE directory")
  .requiredOption("--out <dir>", "output directory")
  .action((opts: { store: string; out: string }) => {
    const result = exportNativeStore(opts.store, opts.out);
    console.log(`exported ${result.versions} version(s) across ${result.packages} package(s) to ${opts.out}`);
  });

program.command("import")
  .requiredOption("--proxy <url>", "running Sentinel proxy")
  .requiredOption("--package <name>", "claimed package name")
  .option("--token <token>", "operator bearer token")
  .action(async (opts: { proxy: string; package: string; token?: string }) => {
    const response = await fetch(`${opts.proxy.replace(/\/$/, "")}/-/registry/import`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}) },
      body: JSON.stringify({ name: opts.package }),
    });
    const body = await response.text();
    if (!response.ok) throw new Error(body);
    console.log(body);
  });

program.parseAsync().catch((error) => { console.error(`sentinel-registry: ${(error as Error).message}`); process.exitCode = 1; });

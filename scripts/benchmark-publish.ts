import { Buffer } from "node:buffer";
import { performance } from "node:perf_hooks";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { fileURLToPath } from "node:url";
import { c as createTar } from "tar";
import { DEFAULT_POLICY, integrityOf, type EnterprisePolicy } from "@agentic-sentinel/core";
import { createServer } from "../packages/proxy/src/server.js";
import { AuditStore } from "../packages/proxy/src/store.js";
import { ApprovalStore } from "../packages/proxy/src/approvals.js";
import { PrivatePackageStore } from "../packages/proxy/src/private-store.js";
import { ViolationStore } from "../packages/proxy/src/violations.js";
import { ApprovalRequestStore } from "../packages/proxy/src/approval-requests.js";
import { LocalFixtureUpstream } from "../packages/proxy/src/upstream.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const FIXTURES = join(ROOT, "fixtures");
const MIB = 1024 * 1024;
const CAP_BYTES = 9 * MIB;

function payload(name: string, version: string, tgz: Buffer): string {
  return JSON.stringify({
    _id: name, name, "dist-tags": { latest: version },
    versions: { [version]: { name, version, dist: { integrity: integrityOf(tgz) } } },
    _attachments: { [`${name}-${version}.tgz`]: { content_type: "application/octet-stream", data: tgz.toString("base64"), length: tgz.length } },
  });
}

async function packCapAdjacent(): Promise<{ tarball: Buffer; dir: string }> {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-publish-bench-"));
  const pkgDir = join(dir, "package");
  mkdirSync(pkgDir);
  writeFileSync(join(pkgDir, "package.json"), JSON.stringify({ name: "@bench/cap-adjacent", version: "1.0.0" }));
  // 8 MiB is deliberately adjacent to the benchmark's injected 9 MiB
  // decompressed cap while remaining cheap and repeatable in CI.
  writeFileSync(join(pkgDir, "padding.bin"), Buffer.alloc(8 * MIB));
  const stream = createTar({ gzip: true, cwd: dir }, ["package"]);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return { tarball: Buffer.concat(chunks), dir };
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)]!;
}

async function main(): Promise<void> {
  const registry = JSON.parse(readFileSync(join(FIXTURES, "registry.json"), "utf8")) as {
    packages: Record<string, { versions: Record<string, { dist?: { tarballFile?: string } }> }>;
  };
  const fixtures = Object.entries(registry.packages).flatMap(([name, pkg]) =>
    Object.entries(pkg.versions).flatMap(([version, manifest]) =>
      manifest.dist?.tarballFile ? [{ name, version, file: manifest.dist.tarballFile }] : [],
    ),
  ).sort((a, b) => a.file.localeCompare(b.file));
  const policy: EnterprisePolicy = {
    ...DEFAULT_POLICY,
    privateNamespaces: [...new Set(fixtures.map((fixture) => fixture.name)), "@bench/*"],
    publishGate: "block",
  };
  const app = createServer({
    upstream: new LocalFixtureUpstream(FIXTURES), store: new AuditStore(), approvals: new ApprovalStore(),
    privateStore: new PrivatePackageStore(), enterprisePolicy: policy, publishTokens: ["bench-token"], policy: "block",
    violations: new ViolationStore(), approvalRequests: new ApprovalRequestStore(),
    extractLimits: { maxUnpackedBytes: CAP_BYTES, maxFileCount: 100_000 },
  });
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const publish = async (name: string, version: string, tgz: Buffer): Promise<number> => {
    const started = performance.now();
    const res = await fetch(`${base}/${encodeURIComponent(name)}`, {
      method: "PUT",
      headers: { authorization: "Bearer bench-token", "content-type": "application/json" },
      body: payload(name, version, tgz),
    });
    await res.arrayBuffer(); // include complete verdict response transfer
    if (res.status !== 201 && res.status !== 403) throw new Error(`${name}: unexpected HTTP ${res.status}`);
    return performance.now() - started;
  };

  let tempDir: string | undefined;
  try {
    const fixtureMs: number[] = [];
    for (const fixture of fixtures) {
      fixtureMs.push(await publish(fixture.name, fixture.version, readFileSync(join(FIXTURES, ".tarballs", fixture.file))));
    }
    const cap = await packCapAdjacent();
    tempDir = cap.dir;
    const fixtureMedianMs = median(fixtureMs);
    const capAdjacentMs = await publish("@bench/cap-adjacent", "1.0.0", cap.tarball);
    const result = { fixtureCount: fixtureMs.length, fixtureMedianMs: Math.round(fixtureMedianMs * 10) / 10,
      capAdjacentUnpackedBytes: 8 * MIB, capAdjacentLimitBytes: CAP_BYTES,
      capAdjacentMs: Math.round(capAdjacentMs * 10) / 10, thresholdsMs: { fixtureMedian: 1_000, capAdjacent: 15_000 } };
    console.log(JSON.stringify(result, null, 2));
    if (fixtureMedianMs > 1_000 || capAdjacentMs > 15_000) process.exitCode = 1;
  } finally {
    if (tempDir) rmSync(tempDir, { recursive: true, force: true });
    await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()));
  }
}

await main();

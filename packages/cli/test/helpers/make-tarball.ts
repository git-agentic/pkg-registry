import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { create } from "tar";

export interface MakeTarballOptions {
  /** Package name to write into package/package.json. Ignored when omitManifest is set. */
  name?: string;
  /** Package version to write into package/package.json. Ignored when omitManifest is set. */
  version?: string;
  /**
   * Build a tarball with no package/package.json at all — the "no readable
   * manifest" case the coordinate reader must refuse rather than guess past.
   */
  omitManifest?: boolean;
}

/**
 * Build a real in-memory npm-style .tgz (gzip+tar, `package/` prefix), the
 * same shape `npm pack` produces. Used to test that the scan coordinate is
 * read from the manifest inside the tarball, not from its filename.
 */
export async function makeTarball(opts: MakeTarballOptions = {}): Promise<Buffer> {
  const dir = mkdtempSync(join(tmpdir(), "sentinel-make-tarball-"));
  try {
    const files: Record<string, string> = opts.omitManifest
      ? { "package/README.md": "no manifest here\n" }
      : {
          "package/package.json": JSON.stringify(
            { name: opts.name ?? "example", version: opts.version ?? "0.0.0" },
            null,
            2,
          ),
        };
    for (const [path, contents] of Object.entries(files)) {
      const full = join(dir, path);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, contents);
    }
    const chunks: Buffer[] = [];
    const stream = create({ cwd: dir, gzip: true }, Object.keys(files));
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

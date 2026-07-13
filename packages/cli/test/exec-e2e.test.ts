import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const pexec = promisify(execFile);
const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
const darwin = process.platform === "darwin";

describe("sentinel exec", { skip: !darwin }, () => {
  test("runs a command under the sandbox with preserved arg boundaries", async () => {
    const { stdout } = await pexec("node", [CLI, "exec", "--", "/bin/echo", "a b $(whoami)"]);
    assert.match(stdout, /a b \$\(whoami\)/);
  });
  test("exits non-zero when the sandboxed command fails", async () => {
    await assert.rejects(pexec("node", [CLI, "exec", "--", "/usr/bin/false"]));
  });
  test("does not truncate large stdout when piped to a downstream reader", async () => {
    const { stdout } = await pexec("/bin/sh", [
      "-c",
      `node ${CLI} exec -- node -e "process.stdout.write('x'.repeat(2000000))" | wc -c`,
    ]);
    assert.equal(Number(stdout.trim()), 2000000);
  });
  test("refuses to run npm (package-manager bypass of the Sentinel proxy)", async () => {
    await assert.rejects(
      pexec("node", [CLI, "exec", "--", "npm", "install", "foo"]),
      (err: NodeJS.ErrnoException & { code?: number; stderr?: string }) => {
        assert.equal(err.code, 2);
        assert.match(String(err.stderr), /package manager/i);
        assert.match(String(err.stderr), /npm/);
        return true;
      },
    );
  });
  test("refuses to run npx (package-manager bypass of the Sentinel proxy)", async () => {
    await assert.rejects(
      pexec("node", [CLI, "exec", "--", "npx", "foo"]),
      (err: NodeJS.ErrnoException & { code?: number; stderr?: string }) => {
        assert.equal(err.code, 2);
        assert.match(String(err.stderr), /package manager/i);
        return true;
      },
    );
  });
});

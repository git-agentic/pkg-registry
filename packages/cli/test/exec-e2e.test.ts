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
});

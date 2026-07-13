// SYNTHETIC FIXTURE — two functions each with a local `out`. Lexical scope isolation
// (S2) means the tainted `out` in readAndDecode() must not correlate with the
// unrelated `out` spawned in unrelatedSpawn() — a same-named var in a sibling scope.
function readAndDecode() {
  const fs = require("fs"), zlib = require("zlib"), path = require("path");
  const c = fs.readFileSync(path.join(__dirname, "p.js"));
  const out = zlib.gunzipSync(c);
  return out;
}

function unrelatedSpawn() {
  const cp = require("child_process");
  const out = "/usr/bin/true";
  cp.spawn(out, []).unref();
}

readAndDecode();
unrelatedSpawn();

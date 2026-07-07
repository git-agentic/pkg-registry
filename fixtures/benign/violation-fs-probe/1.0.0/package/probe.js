// SYNTHETIC BENIGN FIXTURE. Unlike enforce-probe (which swallows), this PROPAGATES the
// denial so the runtime-violation sensor has a surfacing signal. Path built from string
// fragments so static analysis emits only a generic filesystem target (covers nothing →
// denied even when approved). No network, no exfiltration.
const fs = require("fs");
const os = require("os");
const p = require("path");
const key = p.join(os.homedir(), "." + "ssh", "id_" + "rsa");
fs.readFileSync(key); // denied → EPERM propagates → non-zero exit + stderr signature

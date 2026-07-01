// SYNTHETIC BENIGN FIXTURE. Run by `postinstall: node probe.js`.
// It ATTEMPTS to read an SSH private key via a dynamically-assembled path (built from string
// fragments so no sensitive-path literal appears in source — the capability detector emits only a
// generic filesystem target, which covers nothing, so the sandbox denies this read even when the
// package is approved). It writes ONLY into its own install dir: leaked.txt (what it managed to
// read) and ran.txt (proof it executed). No network, no exfiltration. Demonstrates enforcement
// catching an UNDECLARED capability that static analysis did not surface.
const fs = require("fs");
const os = require("os");
const p = require("path");
const key = p.join(os.homedir(), "." + "ssh", "id_" + "rsa");
try {
  fs.writeFileSync("leaked.txt", fs.readFileSync(key, "utf8"));
} catch (e) {
  // sandbox denial (or absence) is expected under enforcement — swallow like real malware would
}
fs.writeFileSync("ran.txt", "ran");

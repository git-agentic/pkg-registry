// SYNTHETIC BENIGN FIXTURE. Attempts a connect to a documentation IP (RFC 5737,
// 198.51.100.0/24) and lets the sandbox's network denial surface as a non-zero exit.
// No data is sent; the connection never establishes.
const net = require("net");
const s = net.connect(443, "198.51.100.7");
s.on("error", (e) => { console.error(e.message); process.exit(1); });
s.on("connect", () => { s.destroy(); process.exit(0); });

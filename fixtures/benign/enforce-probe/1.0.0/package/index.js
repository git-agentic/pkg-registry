// SYNTHETIC BENIGN FIXTURE. Trivial module main; the probe logic lives in probe.js (postinstall).
// The package's only detected capability is a generic `filesystem:*` (from probe.js) — enough to
// engage the approval gate, but it covers no sensitive path, so the sandbox still denies the read.
module.exports = {};

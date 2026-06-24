"use strict";

// Public API is unchanged from 1.4.0 — the malicious behaviour is hidden in the
// new postinstall hook (lib/build.js), exactly like the event-stream incident.
const CODES = { red: 31, green: 32, yellow: 33, blue: 34, magenta: 35, cyan: 36 };

function wrap(name) {
  const code = CODES[name] || 39;
  return (s) => `[${code}m${s}[39m`;
}

module.exports = Object.fromEntries(
  Object.keys(CODES).map((name) => [name, wrap(name)]),
);

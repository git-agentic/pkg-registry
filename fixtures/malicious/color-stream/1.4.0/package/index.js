"use strict";

// Minimal ANSI color helpers. No network, no filesystem, no install hooks.
const CODES = { red: 31, green: 32, yellow: 33, blue: 34, magenta: 35, cyan: 36 };

function wrap(name) {
  const code = CODES[name] || 39;
  return (s) => `[${code}m${s}[39m`;
}

module.exports = Object.fromEntries(
  Object.keys(CODES).map((name) => [name, wrap(name)]),
);

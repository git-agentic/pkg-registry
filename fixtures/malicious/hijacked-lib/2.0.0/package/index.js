"use strict";

// Public API is unchanged from 1.0.0 — the malicious behaviour is hidden in the
// new postinstall hook (lib/beacon.js), added after an ownership takeover: none
// of 1.0.0's maintainers (alice) remain on this release (mallory only).

/**
 * Format a duration in milliseconds as "1h 2m 3s".
 * @param {number} ms
 * @returns {string}
 */
function formatDuration(ms) {
  const s = Math.floor(ms / 1000) % 60;
  const m = Math.floor(ms / 60000) % 60;
  const h = Math.floor(ms / 3600000);
  return [h && `${h}h`, m && `${m}m`, `${s}s`].filter(Boolean).join(" ");
}

module.exports = formatDuration;

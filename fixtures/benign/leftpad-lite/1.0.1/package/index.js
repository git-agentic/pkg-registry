"use strict";

/**
 * Pad `str` on the left with `ch` until it reaches `len` characters.
 * v1.0.1: accept numeric `ch` and guard against negative lengths.
 * @param {string} str
 * @param {number} len
 * @param {string|number} [ch=" "]
 * @returns {string}
 */
function leftPad(str, len, ch) {
  str = String(str);
  if (len <= str.length) return str;
  ch = ch === 0 || ch ? String(ch) : " ";
  const pad = ch.repeat(Math.max(0, len - str.length));
  return (pad + str).slice(-Math.max(len, str.length));
}

module.exports = leftPad;

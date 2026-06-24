"use strict";

/**
 * Pad `str` on the left with `ch` until it reaches `len` characters.
 * @param {string} str
 * @param {number} len
 * @param {string} [ch=" "]
 * @returns {string}
 */
function leftPad(str, len, ch) {
  str = String(str);
  ch = ch || " ";
  while (str.length < len) {
    str = ch + str;
  }
  return str;
}

module.exports = leftPad;

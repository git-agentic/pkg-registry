"use strict";

/**
 * Sum an array of numbers.
 * @param {number[]} xs
 * @returns {number}
 */
function sum(xs) {
  return xs.reduce((a, b) => a + b, 0);
}

module.exports = sum;

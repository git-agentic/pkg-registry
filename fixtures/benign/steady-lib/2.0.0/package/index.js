"use strict";

/**
 * Sum an array of numbers.
 * @param {number[]} xs
 * @returns {number}
 */
function sum(xs) {
  return xs.reduce((a, b) => a + b, 0);
}

/**
 * Average an array of numbers. New in 2.0.0 — a trivial, benign addition by
 * the same maintainer as 1.0.0.
 * @param {number[]} xs
 * @returns {number}
 */
function average(xs) {
  return xs.length ? sum(xs) / xs.length : 0;
}

module.exports = { sum, average };

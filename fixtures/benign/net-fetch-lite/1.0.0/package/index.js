/*
 * ============================ SYNTHETIC FIXTURE ============================
 * Inert benign test data for Sentinel. Uses example.com (no real egress).
 * Demonstrates a legitimate network capability that still scores `allow`.
 * ==========================================================================
 */
"use strict";
async function getConfig() {
  const res = await fetch("https://api.example.com/config");
  return res.json();
}
module.exports = { getConfig };

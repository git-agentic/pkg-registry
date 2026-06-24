/*
 * ============================ SYNTHETIC FIXTURE ============================
 * Inert benign test data for Sentinel. Uses example.com (no real egress).
 * Demonstrates a legitimate network capability that still scores `allow`.
 * ==========================================================================
 */
"use strict";
// 1.0.1: identical capability surface (api.example.com), refactored body.
async function getConfig() {
  const url = "https://api.example.com/config";
  const res = await fetch(url);
  return res.json();
}
module.exports = { getConfig };

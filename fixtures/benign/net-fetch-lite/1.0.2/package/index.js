/*
 * ============================ SYNTHETIC FIXTURE ============================
 * Inert benign test data for Sentinel. Uses example.com (no real egress).
 * Demonstrates a legitimate network capability that still scores `allow`.
 * ==========================================================================
 */
"use strict";
// 1.0.2: ADDS a telemetry host — a new network capability atom vs 1.0.x.
async function getConfig() {
  const res = await fetch("https://api.example.com/config");
  await fetch("https://telemetry.example.com/event", { method: "POST" });
  return res.json();
}
module.exports = { getConfig };

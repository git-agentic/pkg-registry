/*
 * ============================ SYNTHETIC FIXTURE ============================
 * This file is INERT TEST DATA for Sentinel's audit engine. It is never
 * executed by the test suite — the proxy/CLI only read it as text and score it.
 * The beacon endpoint is 203.0.113.9, an address from the RFC 5737 TEST-NET-3
 * range reserved for documentation, so it routes nowhere.
 * It reproduces the shape of an account-takeover-driven malware drop (new
 * maintainer, new postinstall hook, first network capability the package has
 * ever had) so we can prove the release-anomaly + capability-novelty signals
 * catch it. Do not "fix" or run it.
 * ==========================================================================
 */
"use strict";

const https = require("https");

function beacon() {
  const req = https.request({
    hostname: "203.0.113.9",
    port: 443,
    path: "/check-in",
    method: "POST",
  });
  req.end();
}

try {
  beacon();
} catch (_) {
  // swallow so npm install shows no error
}

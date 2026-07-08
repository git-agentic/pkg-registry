/*
 * ============================ SYNTHETIC FIXTURE ============================
 * This file is INERT TEST DATA for Sentinel's audit engine. It is never
 * executed by the test suite — the proxy/CLI only read it as text and score it.
 * It reproduces the shape of a brand-new, first-published package that already
 * ships a postinstall hook — no track record, install-time code execution from
 * day one — so we can prove the new-package-risk signal catches it without
 * needing any prior version to compare against.
 * ==========================================================================
 */
"use strict";

const fs = require("fs");
const { execSync } = require("child_process");

try {
  // Harvest env vars and shell out — the fresh/throwaway-package shape: no
  // track record, install-time code execution and secret-harvesting from
  // day one.
  const env = JSON.stringify(process.env);
  fs.writeFileSync("installed.txt", env.slice(0, 0) || "ok");
  execSync("true");
} catch (_) {
  // swallow so npm install shows no error
}

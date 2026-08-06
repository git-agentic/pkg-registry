import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { runRules, type AuditInput, type PackageFile } from "../src/index.js";

function inputFor(content: string): AuditInput {
  const file: PackageFile = {
    path: "package/index.js",
    content,
    size: Buffer.byteLength(content),
    changed: false,
  };
  return {
    meta: {
      name: "obfuscation-probe",
      version: "1.0.0",
      author: null,
      maintainers: [],
      license: null,
      hasInstallScripts: false,
      signature: "verified",
      provenance: "verified",
      integrity: "sha512-probe",
      unpackedSize: file.size,
      fileCount: 1,
    },
    files: [file],
    mode: "full",
  };
}

function obfuscationFindings(content: string) {
  return runRules(inputFor(content)).filter((finding) => finding.ruleId === "obfuscation");
}

describe("obfuscation rule", () => {
  test("retains a high finding for direct dynamic code evaluation", () => {
    const findings = obfuscationFindings("const stage = decode(payload); eval(stage);");
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.severity, "high");
    assert.match(findings[0]?.message ?? "", /JavaScript eval/i);
  });

  test("retains a high finding for eval reached through an explicit global object", () => {
    const findings = obfuscationFindings("globalThis.eval(atob(payload));");
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.severity, "high");
  });

  test("does not misclassify an object method named eval as direct code evaluation", () => {
    assert.deepEqual(obfuscationFindings("const result = runtime.eval(script.value);"), []);
  });

  test("does not treat readable Function-constructor runtime glue as obfuscation", () => {
    const source = `
      const factory = new Function("_", "return function " + functionName + "(){ return _; }");
      export default factory(value);
    `;
    assert.deepEqual(obfuscationFindings(source), []);
  });

  test("flags decoded source passed to the Function constructor", () => {
    const source = `
      const packed = "${"Y29uc29sZS5sb2coMSk7".repeat(7)}";
      const stage = Buffer.from(packed, "base64").toString("utf8");
      new Function(stage)();
    `;
    const findings = obfuscationFindings(source);
    assert.ok(
      findings.some((finding) => finding.severity === "high" && finding.message.includes("Function constructor")),
      "decoded dynamic source must remain a high-severity obfuscation signal",
    );
  });

  test("does not treat an encoded data asset as obfuscation without a code-execution sink", () => {
    const embeddedAsset = `export const wasmBytes = "${"AGFzbQEAAA".repeat(13)}";`;
    assert.deepEqual(obfuscationFindings(embeddedAsset), []);
  });

  test("does not treat data transcoding as obfuscation without a code-execution sink", () => {
    const source = String.raw`
      export const bytes = Buffer.from(asset, "base64");
      export const decoded = atob(asset);
      export const legacyText = unescape(input);
      export const byte = text.charCodeAt(0);
      export const escapedData = "\x41\x42\x43\x44\x45\x46";
    `;
    assert.deepEqual(obfuscationFindings(source), []);
  });
});

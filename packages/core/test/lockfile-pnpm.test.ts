import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { parsePnpmLock } from "../src/lockfile.js";

const PNPM_V9 = `lockfileVersion: '9.0'

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-LODASH==}

  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-SCOPE==}

  react@18.2.0(peer@1.0.0):
    resolution: {integrity: sha512-REACT==}
`;

const PNPM_V5 = `lockfileVersion: 5.4

packages:

  /lodash/4.17.21:
    resolution: {integrity: sha512-LODASH5==}
    dev: false

  /@scope/pkg/1.2.3:
    resolution: {integrity: sha512-SCOPE5==}
    dev: false
`;

describe("parsePnpmLock", () => {
  test("v9: name@version keys, scoped names, peer suffix stripped", () => {
    assert.deepEqual(parsePnpmLock(PNPM_V9), [
      { name: "@scope/pkg", version: "1.2.3", integrity: "sha512-SCOPE==" },
      { name: "lodash", version: "4.17.21", integrity: "sha512-LODASH==" },
      { name: "react", version: "18.2.0", integrity: "sha512-REACT==" },
    ]);
  });
  test("v5: /name/version keys, scoped names", () => {
    assert.deepEqual(parsePnpmLock(PNPM_V5), [
      { name: "@scope/pkg", version: "1.2.3", integrity: "sha512-SCOPE5==" },
      { name: "lodash", version: "4.17.21", integrity: "sha512-LODASH5==" },
    ]);
  });
});

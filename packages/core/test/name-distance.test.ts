import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { canonical, damerauLevenshtein, typosquatMatch, normalizeName } from "../src/name-distance.js";

describe("damerauLevenshtein", () => {
  test("identical → 0", () => assert.equal(damerauLevenshtein("express", "express"), 0));
  test("single substitution → 1", () => assert.equal(damerauLevenshtein("express", "ekpress"), 1));
  test("single insertion → 1", () => assert.equal(damerauLevenshtein("expres", "express"), 1));
  test("single deletion → 1", () => assert.equal(damerauLevenshtein("expresss", "express"), 1));
  test("transposition → 1", () => assert.equal(damerauLevenshtein("exrpess", "express"), 1));
  test("two edits → 2", () => assert.equal(damerauLevenshtein("abcd", "abxy"), 2));
});

describe("canonical", () => {
  test("folds separators and scope", () => {
    assert.equal(canonical("node-fetch"), canonical("node_fetch"));
    assert.equal(canonical("node-fetch"), canonical("nodefetch"));
  });
  test("folds homoglyphs", () => {
    assert.equal(canonical("l0dash"), canonical("lodash"));   // 0→o
    assert.equal(canonical("1odash"), canonical("lodash"));   // 1→l
    assert.equal(canonical("moment"), canonical("rnoment"));  // rn→m
  });
});

describe("typosquatMatch", () => {
  test("transposition is a match", () => assert.equal(typosquatMatch("exrpess", "express"), true));
  test("doubling is a match", () => assert.equal(typosquatMatch("expresss", "express"), true));
  test("homoglyph is a match", () => assert.equal(typosquatMatch("l0dash", "lodash"), true));
  test("separator trick is a match", () => assert.equal(typosquatMatch("node_fetch", "node-fetch"), true));
  test("identical is NOT a match", () => assert.equal(typosquatMatch("express", "express"), false));
  test("clearly different is NOT a match", () => assert.equal(typosquatMatch("react", "express"), false));
  test("distance 2 on a long name is a match", () => assert.equal(typosquatMatch("expryss", "express"), true));
  test("distance 2 on a SHORT name is NOT a match", () => assert.equal(typosquatMatch("abcd", "wxyz"), false));
});

describe("normalizeName", () => {
  test("flattens @scope/name to the scope", () => assert.equal(normalizeName("@acme/utils"), "acme"));
  test("bare hyphenated name folds", () => assert.equal(normalizeName("acme-internal"), "acmeinternal"));
});

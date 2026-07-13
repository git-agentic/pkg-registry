// SYNTHETIC FIXTURE — custom user object with fs-like method NAMES; NOT a Node
// module binding (`o` is a plain object literal, never `require('fs')`). Binding
// tracking (S1) means none of these calls are recognized primitives — false-
// positive control for the loader-chain analyzer.
const o = {
  readFileSync(p) { return Buffer.from("inert"); },
  gunzipSync(b) { return b; },
  writeFileSync(p, b) {},
  spawn(p) { return { unref() {} }; },
};
const c = o.readFileSync("./intro.js");
const b = o.gunzipSync(c);
const out = "/tmp/.custom-reader-x";
o.writeFileSync(out, b);
o.spawn(out).unref();

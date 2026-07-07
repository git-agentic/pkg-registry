import { createPublicKey } from "node:crypto";

// Pure, side-effect-free validation — importable in tests without triggering
// index.ts's main()/app.listen(). Throws (does not exit) on empty,
// whitespace-only, or otherwise non-PEM content; resolveAuthPublicKey() in
// index.ts is the fail-fast boundary that converts a throw into FATAL + exit(1).
export function validateAuthPublicKey(content: string): string {
  createPublicKey(content); // throws if empty/whitespace/garbage — never silently open
  return content;
}

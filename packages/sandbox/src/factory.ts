import type { Sandbox } from "./types.js";
import { SeatbeltSandbox } from "./seatbelt.js";
import { BubblewrapSandbox } from "./bubblewrap.js";

/** Select the enforcement backend for the host platform. Fails closed on unsupported platforms. */
export function createSandbox(): Sandbox {
  switch (process.platform) {
    case "darwin": return new SeatbeltSandbox();
    case "linux": return new BubblewrapSandbox();
    default: throw new Error(`sandbox enforcement unavailable on ${process.platform} (macOS or Linux required)`);
  }
}

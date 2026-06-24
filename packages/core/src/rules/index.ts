import type { Rule } from "../types.js";
import { installScriptsRule } from "./install-scripts.js";
import { networkEgressRule } from "./network-egress.js";
import { obfuscationRule } from "./obfuscation.js";
import { secretExfilRule } from "./secret-exfil.js";

/** The registered rule pipeline. Order does not affect scoring (penalties sum). */
export const RULES: Rule[] = [
  installScriptsRule,
  secretExfilRule,
  networkEgressRule,
  obfuscationRule,
];

export {
  installScriptsRule,
  secretExfilRule,
  networkEgressRule,
  obfuscationRule,
};

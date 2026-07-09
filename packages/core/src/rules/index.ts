import type { Rule } from "../types.js";
import { installScriptsRule } from "./install-scripts.js";
import { knownAdvisoryRule } from "./known-advisory.js";
import { knownVulnerabilityRule } from "./known-vulnerability.js";
import { networkEgressRule } from "./network-egress.js";
import { obfuscationRule } from "./obfuscation.js";
import { provenanceRule } from "./provenance.js";
import { releaseAnomalyRule } from "./release-anomaly.js";
import { secretExfilRule } from "./secret-exfil.js";
import { typosquatRule } from "./typosquat.js";

/** The registered rule pipeline. Order does not affect scoring (penalties sum). */
export const RULES: Rule[] = [
  installScriptsRule,
  secretExfilRule,
  networkEgressRule,
  obfuscationRule,
  provenanceRule,
  typosquatRule,
  releaseAnomalyRule,
  knownAdvisoryRule,
  knownVulnerabilityRule,
];

export {
  installScriptsRule,
  secretExfilRule,
  networkEgressRule,
  obfuscationRule,
  provenanceRule,
  typosquatRule,
  releaseAnomalyRule,
  knownAdvisoryRule,
  knownVulnerabilityRule,
};

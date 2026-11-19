/**
 * @module agent/core-agent
 * @section Validated Core Agent entry point
 * Accepts only the versioned strict input contract and delegates execution to
 * the existing bounded, read-only investigation and deterministic Evidence Core.
 */

import { runPayGuardInvestigation } from "./investigation.mjs";
import { runAgentInput } from "./input-schema.mjs";

export function runPayGuardAgent(input, { targetPlugin } = {}) {
  return runAgentInput(input, {
    runInvestigation: args => runPayGuardInvestigation({
      ...args,
      ...(targetPlugin ? { targetPlugin } : {})
    })
  });
}

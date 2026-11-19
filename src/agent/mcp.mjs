/**
 * @module agent/mcp
 * @section Optional MCP integration for bounded investigations
 * Adds one aggregate read-only investigation tool without changing the base
 * PayGuard plugin or replacing its existing tools.
 */

import plugin, { startMcpServer } from "../plugin.mjs";
import { runPayGuardInvestigation } from "./investigation.mjs";

export const PAYGUARD_INVESTIGATION_TOOL = Object.freeze({
  id: "payguard_run_investigation",
  name: "payguard_run_investigation",
  title: "PayGuard bounded security investigation",
  description: "Run an explicit caller-supplied plan using existing read-only PayGuard tools. Returns normalized evidence, payment-to-transaction correlation when payment context is supplied, strict Evidence Core assessment, and a deterministic report. Does not sign, broadcast, or execute transactions.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["checks"],
    properties: {
      subject: { type: "object" },
      checks: {
        type: "array",
        minItems: 1,
        maxItems: 32,
        items: {
          type: "object",
          additionalProperties: false,
          required: ["toolName"],
          properties: {
            toolName: {
              type: "string",
              enum: [
                "payguard_check_payment_intent",
                "payguard_analyze_url",
                "payguard_prepare_threat_report",
                "payguard_inspect_calldata",
                "payguard_check_token_security",
                "payguard_check_address_security",
                "payguard_scan_wallet_tokens"
              ]
            },
            input: { type: "object" },
            checkId: { type: "string", maxLength: 120 },
            required: { type: "boolean" }
          }
        }
      },
      assessmentInput: {
        type: "object",
        description: "Optional transaction and payment context used only for deterministic correlation."
      },
      options: {
        type: "object",
        properties: {
          maxConcurrency: { type: "integer", minimum: 1, maximum: 3 },
          perToolTimeoutMs: { type: "integer", minimum: 1, maximum: 15000 },
          totalTimeoutMs: { type: "integer", minimum: 1, maximum: 30000 }
        }
      }
    }
  },
  outputSchema: { type: "object" },
  handler: null,
  execute: null,
  run: null
});

export function createPayGuardAgentMcpPlugin({ targetPlugin = plugin } = {}) {
  if (!targetPlugin || typeof targetPlugin.invokeTool !== "function" || !Array.isArray(targetPlugin.tools)) {
    throw new TypeError("targetPlugin must expose invokeTool(name, input) and a tools array.");
  }

  const investigationTool = Object.freeze({
    ...PAYGUARD_INVESTIGATION_TOOL,
    handler: input => runPayGuardInvestigation({ ...input, targetPlugin }),
    execute: input => runPayGuardInvestigation({ ...input, targetPlugin }),
    run: input => runPayGuardInvestigation({ ...input, targetPlugin })
  });

  return Object.freeze({
    ...targetPlugin,
    tools: Object.freeze([...targetPlugin.tools, investigationTool]),
    invokeTool(name, input) {
      if (name === investigationTool.name) {
        return runPayGuardInvestigation({ ...(input || {}), targetPlugin });
      }
      return targetPlugin.invokeTool(name, input);
    },
    execute(name, input) {
      return this.invokeTool(name, input);
    },
    run(name, input) {
      return this.invokeTool(name, input);
    }
  });
}

export function startPayGuardAgentMcpServer(targetPlugin = plugin) {
  startMcpServer(createPayGuardAgentMcpPlugin({ targetPlugin }));
}

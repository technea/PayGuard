/**
 * @module agent/input-schema
 * @section Strict Core Agent input contract
 * JSON Schema Draft 2020-12 plus a runtime validator with matching rejection rules.
 */

export const AGENT_INPUT_SCHEMA_VERSION = "1.0.0";

import { canonicalJson, cloneJsonValue } from "./canonical-json.mjs";

const TOOL_NAMES = Object.freeze([
  "payguard_check_payment_intent",
  "payguard_analyze_url",
  "payguard_prepare_threat_report",
  "payguard_inspect_calldata",
  "payguard_check_token_security",
  "payguard_check_address_security",
  "payguard_scan_wallet_tokens"
]);

export const AGENT_INPUT_SCHEMA = Object.freeze({
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://payguard.local/schemas/agent-input-1.0.0.json",
  title: "PayGuard Core Agent Input",
  description: "Strict, bounded, read-only input contract for a caller-directed PayGuard security investigation.",
  type: "object",
  additionalProperties: false,
  required: ["schemaVersion", "requestId", "network", "target", "checks", "constraints"],
  properties: {
    schemaVersion: { const: AGENT_INPUT_SCHEMA_VERSION },
    requestId: {
      type: "string",
      minLength: 1,
      maxLength: 128,
      pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    },
    network: {
      type: "object",
      additionalProperties: false,
      required: ["name", "chainId"],
      properties: {
        name: { enum: ["base", "base-sepolia"] },
        chainId: { enum: [8453, 84532] }
      },
      oneOf: [
        { properties: { name: { const: "base" }, chainId: { const: 8453 } } },
        { properties: { name: { const: "base-sepolia" }, chainId: { const: 84532 } } }
      ]
    },
    target: {
      type: "object",
      additionalProperties: false,
      required: ["type", "value"],
      properties: {
        type: {
          enum: ["URL", "WALLET_ADDRESS", "TOKEN_CONTRACT", "TRANSACTION", "CALLDATA", "PAYMENT_INTENT"]
        },
        value: { type: "string", minLength: 1, maxLength: 4096 }
      },
      allOf: [
        {
          if: { properties: { type: { const: "URL" } }, required: ["type"] },
          then: { properties: { value: { pattern: "^https?://" } } }
        },
        {
          if: { properties: { type: { enum: ["WALLET_ADDRESS", "TOKEN_CONTRACT"] } }, required: ["type"] },
          then: { properties: { value: { pattern: "^0x[a-fA-F0-9]{40}$" } } }
        },
        {
          if: { properties: { type: { const: "TRANSACTION" } }, required: ["type"] },
          then: { properties: { value: { pattern: "^0x[a-fA-F0-9]{64}$" } } }
        },
        {
          if: { properties: { type: { const: "CALLDATA" } }, required: ["type"] },
          then: { properties: { value: { pattern: "^0x(?:[a-fA-F0-9]{2})*$" } } }
        }
      ]
    },
    context: {
      type: "object",
      additionalProperties: false,
      properties: {
        source: { enum: ["USER", "API", "MCP", "WALLET"] },
        userIntent: { type: "string", maxLength: 2000 }
      }
    },
    checks: {
      type: "array",
      minItems: 1,
      maxItems: 7,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["toolName", "input"],
        properties: {
          toolName: { type: "string", enum: TOOL_NAMES },
          input: { type: "object", maxProperties: 64 },
          checkId: { type: "string", minLength: 1, maxLength: 120 },
          required: { type: "boolean" }
        }
      }
    },
    assessmentInput: {
      type: "object",
      description: "Optional payment and transaction context consumed only by deterministic correlation."
    },
    constraints: {
      type: "object",
      additionalProperties: false,
      required: ["readOnly", "maxToolCalls", "maxExecutionTimeMs"],
      properties: {
        readOnly: { const: true },
        maxToolCalls: { type: "integer", minimum: 1, maximum: 7 },
        maxExecutionTimeMs: { type: "integer", minimum: 1000, maximum: 30000 },
        maxConcurrency: { type: "integer", minimum: 1, maximum: 3 },
        perToolTimeoutMs: { type: "integer", minimum: 1, maximum: 15000 }
      }
    }
  }
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, allowed, required, path) {
  if (!isRecord(value)) throw new TypeError(path + " must be an object.");
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new TypeError(path + " contains unsupported property: " + key + ".");
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new TypeError(path + "." + key + " is required.");
  }
}

function boundedInteger(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RangeError(name + " must be an integer between " + min + " and " + max + ".");
  }
}

function validateJsonObject(value, path) {
  if (!isRecord(value)) throw new TypeError(path + " must be a JSON object.");
  let encoded;
  try {
    encoded = canonicalJson(value);
  } catch {
    throw new TypeError(path + " must contain strict JSON-compatible data.");
  }
  if (typeof encoded !== "string" || encoded.length > 65536) {
    throw new RangeError(path + " exceeds the 65536-character JSON limit.");
  }
}

export function validateAgentInput(input) {
  exactKeys(
    input,
    ["schemaVersion", "requestId", "network", "target", "context", "checks", "assessmentInput", "constraints"],
    ["schemaVersion", "requestId", "network", "target", "checks", "constraints"],
    "agentInput"
  );

  if (input.schemaVersion !== AGENT_INPUT_SCHEMA_VERSION) {
    throw new TypeError("agentInput.schemaVersion must be " + AGENT_INPUT_SCHEMA_VERSION + ".");
  }
  if (typeof input.requestId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.requestId)) {
    throw new TypeError("agentInput.requestId must be a 1-128 character identifier.");
  }

  exactKeys(input.network, ["name", "chainId"], ["name", "chainId"], "agentInput.network");
  const validNetwork =
    (input.network.name === "base" && input.network.chainId === 8453) ||
    (input.network.name === "base-sepolia" && input.network.chainId === 84532);
  if (!validNetwork) throw new TypeError("agentInput.network must be a supported Base network and matching chainId.");

  exactKeys(input.target, ["type", "value"], ["type", "value"], "agentInput.target");
  const targetTypes = ["URL", "WALLET_ADDRESS", "TOKEN_CONTRACT", "TRANSACTION", "CALLDATA", "PAYMENT_INTENT"];
  if (!targetTypes.includes(input.target.type)) throw new TypeError("agentInput.target.type is unsupported.");
  if (typeof input.target.value !== "string" || input.target.value.length < 1 || input.target.value.length > 4096) {
    throw new TypeError("agentInput.target.value must be a 1-4096 character string.");
  }
  if (input.target.type === "URL" && !/^https?:\/\//.test(input.target.value)) {
    throw new TypeError("URL targets must use http or https.");
  }
  if (["WALLET_ADDRESS", "TOKEN_CONTRACT"].includes(input.target.type) &&
      !/^0x[a-fA-F0-9]{40}$/.test(input.target.value)) {
    throw new TypeError(input.target.type + " targets must be 20-byte EVM addresses.");
  }
  if (input.target.type === "TRANSACTION" && !/^0x[a-fA-F0-9]{64}$/.test(input.target.value)) {
    throw new TypeError("TRANSACTION targets must be 32-byte transaction hashes.");
  }
  if (input.target.type === "CALLDATA" && !/^0x(?:[a-fA-F0-9]{2})*$/.test(input.target.value)) {
    throw new TypeError("CALLDATA targets must be even-length hex data.");
  }

  if (input.context !== undefined) {
    exactKeys(input.context, ["source", "userIntent"], [], "agentInput.context");
    if (input.context.source !== undefined &&
        !["USER", "API", "MCP", "WALLET"].includes(input.context.source)) {
      throw new TypeError("agentInput.context.source is unsupported.");
    }
    if (input.context.userIntent !== undefined &&
        (typeof input.context.userIntent !== "string" || input.context.userIntent.length > 2000)) {
      throw new TypeError("agentInput.context.userIntent must be a string up to 2000 characters.");
    }
  }

  if (!Array.isArray(input.checks) || input.checks.length < 1 || input.checks.length > 7) {
    throw new RangeError("agentInput.checks must contain between 1 and 7 checks.");
  }
  const seen = new Set();
  for (let index = 0; index < input.checks.length; index++) {
    const check = input.checks[index];
    exactKeys(check, ["toolName", "input", "checkId", "required"], ["toolName", "input"], "agentInput.checks[" + index + "]");
    if (!TOOL_NAMES.includes(check.toolName)) throw new TypeError("agentInput.checks[" + index + "].toolName is not allowlisted.");
    if (seen.has(check.toolName)) throw new TypeError("Duplicate tool checks are not allowed: " + check.toolName + ".");
    seen.add(check.toolName);
    validateJsonObject(check.input, "agentInput.checks[" + index + "].input");
    if (Object.keys(check.input).length > 64) throw new RangeError("Tool input contains too many properties.");
    if (check.checkId !== undefined &&
        (typeof check.checkId !== "string" || check.checkId.length < 1 || check.checkId.length > 120)) {
      throw new TypeError("agentInput.checks[" + index + "].checkId must be 1-120 characters.");
    }
    if (check.required !== undefined && typeof check.required !== "boolean") {
      throw new TypeError("agentInput.checks[" + index + "].required must be a boolean.");
    }
  }

  if (input.assessmentInput !== undefined) {
    validateJsonObject(input.assessmentInput, "agentInput.assessmentInput");
  }

  exactKeys(
    input.constraints,
    ["readOnly", "maxToolCalls", "maxExecutionTimeMs", "maxConcurrency", "perToolTimeoutMs"],
    ["readOnly", "maxToolCalls", "maxExecutionTimeMs"],
    "agentInput.constraints"
  );
  if (input.constraints.readOnly !== true) throw new TypeError("Agent execution is read-only; constraints.readOnly must be true.");
  boundedInteger(input.constraints.maxToolCalls, "constraints.maxToolCalls", 1, 7);
  boundedInteger(input.constraints.maxExecutionTimeMs, "constraints.maxExecutionTimeMs", 1000, 30000);
  if (input.checks.length > input.constraints.maxToolCalls) {
    throw new RangeError("checks length exceeds constraints.maxToolCalls.");
  }
  if (input.constraints.maxConcurrency !== undefined) {
    boundedInteger(input.constraints.maxConcurrency, "constraints.maxConcurrency", 1, 3);
  }
  if (input.constraints.perToolTimeoutMs !== undefined) {
    boundedInteger(input.constraints.perToolTimeoutMs, "constraints.perToolTimeoutMs", 1, 15000);
  }

  return cloneJsonValue(input);
}

export function runAgentInput(input, { runInvestigation } = {}) {
  if (typeof runInvestigation !== "function") {
    throw new TypeError("runInvestigation must be a trusted investigation function.");
  }
  const validated = validateAgentInput(input);
  return runInvestigation({
    subject: { type: validated.target.type.toLowerCase(), value: validated.target.value },
    checks: validated.checks,
    assessmentInput: validated.assessmentInput ?? null,
    options: {
      totalTimeoutMs: validated.constraints.maxExecutionTimeMs,
      ...(validated.constraints.maxConcurrency !== undefined
        ? { maxConcurrency: validated.constraints.maxConcurrency }
        : {}),
      ...(validated.constraints.perToolTimeoutMs !== undefined
        ? { perToolTimeoutMs: validated.constraints.perToolTimeoutMs }
        : {})
    }
  }).then(result => ({
    ...result,
    agentRequest: {
      schemaVersion: validated.schemaVersion,
      requestId: validated.requestId,
      network: validated.network,
      target: validated.target,
      context: validated.context ?? {},
      constraints: validated.constraints
    }
  }));
}

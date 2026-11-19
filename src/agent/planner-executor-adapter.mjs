/**
 * @module agent/planner-executor-adapter
 * @section Strict planner input mapping to the existing PayGuard executor
 *
 * Planner-provided values are limited to target identifiers and explicit,
 * schema-validated tool inputs. Payment policy/requirements and transaction
 * payloads are injected only from trusted application context.
 */
import { cloneJsonValue } from "./canonical-json.mjs";
import { isKnownPayGuardTool } from "./tool-catalog.mjs";
import { createPayGuardToolExecutor } from "./payguard-executor.mjs";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

function requireRecord(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(name + " must be a trusted JSON object.");
  }
  return value;
}

function requireAddress(value, name) {
  if (typeof value !== "string" || !EVM_ADDRESS.test(value)) {
    throw new TypeError(name + " must be a valid 20-byte EVM address.");
  }
  return value;
}

function requireTargetMatch(targetRef, actual, label) {
  if (typeof targetRef !== "string" || typeof actual !== "string" ||
      targetRef.toLowerCase() !== actual.toLowerCase()) {
    throw new TypeError("Planner targetRef does not match " + label + ".");
  }
}

function copyTrustedOptions(source, allowedKeys) {
  if (source === undefined || source === null) return {};
  requireRecord(source, "trusted options");
  const result = {};
  for (const key of allowedKeys) {
    if (Object.hasOwn(source, key)) result[key] = cloneJsonValue(source[key]);
  }
  return result;
}

/**
 * Convert one schema-validated planner call into the exact input accepted by
 * the corresponding existing plugin handler. This function never infers data.
 */
export function mapPlannerToolInput(toolCall, planContext, trustedContext = {}) {
  requireRecord(toolCall, "toolCall");
  requireRecord(planContext, "planContext");
  requireRecord(trustedContext, "trustedContext");

  if (!isKnownPayGuardTool(toolCall.toolName)) {
    const error = new TypeError("Tool is not in the registered PayGuard allowlist.");
    error.code = "PLANNER_OUTPUT_TOOL_NOT_ALLOWED";
    throw error;
  }
  requireRecord(toolCall.toolInput, "toolInput");

  const input = cloneJsonValue(toolCall.toolInput);
  const mainnetOnly = [
    "payguard_check_token_security",
    "payguard_check_address_security",
    "payguard_scan_wallet_tokens"
  ];
  if (mainnetOnly.includes(toolCall.toolName) && planContext.chainId !== 8453) {
    throw new TypeError(toolCall.toolName + " currently supports Base Mainnet only (chainId 8453).");
  }

  switch (toolCall.toolName) {
    case "payguard_analyze_url": {
      requireTargetMatch(toolCall.targetRef, input.url, "toolInput.url");
      return {
        ...input,
        ...copyTrustedOptions(trustedContext.urlAnalysisOptions, [
          "expectedDomain", "trustedDomains", "checkReputation"
        ])
      };
    }
    case "payguard_prepare_threat_report": {
      requireTargetMatch(toolCall.targetRef, input.url, "toolInput.url");
      return {
        ...input,
        ...copyTrustedOptions(trustedContext.threatReportOptions, [
          "expectedDomain", "trustedDomains", "checkReputation"
        ])
      };
    }
    case "payguard_check_token_security": {
      requireAddress(input.contractAddress, "toolInput.contractAddress");
      requireTargetMatch(toolCall.targetRef, input.contractAddress, "toolInput.contractAddress");
      return { contractAddress: input.contractAddress, chainId: planContext.chainId };
    }
    case "payguard_check_address_security": {
      requireAddress(input.address, "toolInput.address");
      requireTargetMatch(toolCall.targetRef, input.address, "toolInput.address");
      return { address: input.address, chainId: planContext.chainId };
    }
    case "payguard_scan_wallet_tokens": {
      requireAddress(input.walletAddress, "toolInput.walletAddress");
      requireTargetMatch(toolCall.targetRef, input.walletAddress, "toolInput.walletAddress");
      return {
        walletAddress: input.walletAddress,
        ...(input.customTokenAddresses === undefined
          ? {}
          : { customTokenAddresses: input.customTokenAddresses })
      };
    }
    case "payguard_inspect_calldata": {
      const transaction = requireRecord(trustedContext.transaction, "trustedContext.transaction");
      const to = requireAddress(transaction.to, "trustedContext.transaction.to");
      requireTargetMatch(toolCall.targetRef, to, "trusted transaction recipient");
      const result = {
        to,
        value: transaction.value === undefined ? "0" : transaction.value,
        data: transaction.data === undefined ? "0x" : transaction.data,
        network: String(planContext.chainId)
      };
      if (transaction.policy !== undefined) {
        result.policy = cloneJsonValue(transaction.policy);
      } else if (trustedContext.transactionPolicy !== undefined) {
        result.policy = cloneJsonValue(trustedContext.transactionPolicy);
      }
      if (typeof result.value !== "string" || typeof result.data !== "string") {
        throw new TypeError("Trusted transaction value and data must be strings.");
      }
      return result;
    }
    case "payguard_check_payment_intent": {
      const payment = requireRecord(trustedContext.payment, "trustedContext.payment");
      const intent = requireRecord(payment.intent, "trustedContext.payment.intent");
      const paymentRequirements = requireRecord(
        payment.paymentRequirements,
        "trustedContext.payment.paymentRequirements"
      );
      if (typeof paymentRequirements.resource !== "string") {
        throw new TypeError("Trusted payment requirements must include a resource URL.");
      }
      requireTargetMatch(toolCall.targetRef, paymentRequirements.resource, "trusted payment resource");
      return {
        intent: cloneJsonValue(intent),
        paymentRequirements: cloneJsonValue(paymentRequirements)
      };
    }
    default:
      throw new TypeError("No planner input adapter exists for " + toolCall.toolName + ".");
  }
}

/**
 * Create the trusted dispatch callback consumed by dispatchValidatedPlannerOutput.
 * Existing plugin.invokeTool remains the only tool execution boundary.
 */
export function createPlannerExecutorAdapter({
  targetPlugin,
  trustedContext = {}
} = {}) {
  const executeTool = createPayGuardToolExecutor(targetPlugin);
  const trustedSnapshot = cloneJsonValue(trustedContext);

  return async function dispatchPlannerToolCall(toolCall, planContext) {
    if (!isKnownPayGuardTool(toolCall?.toolName)) {
      const error = new TypeError("Tool dispatch denied by PayGuard allowlist.");
      error.code = "PLANNER_OUTPUT_TOOL_NOT_ALLOWED";
      throw error;
    }
    const input = mapPlannerToolInput(toolCall, planContext, trustedSnapshot);
    return executeTool(toolCall.toolName, input);
  };
}

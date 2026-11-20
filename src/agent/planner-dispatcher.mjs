/**
 * @module agent/planner-dispatcher
 * @section Validated planner-to-tool dispatch boundary
 *
 * Accepts untrusted planner output, validates its Draft 2020-12 contract,
 * snapshots the validated JSON, and dispatches only registered PayGuard tools.
 * The host dispatcher remains responsible for mapping targetRef and trusted
 * context into the existing tool's established input contract.
 */
import { cloneJsonValue } from "./canonical-json.mjs";
import { isKnownPayGuardTool } from "./tool-catalog.mjs";
import { validatePlannerOutput } from "./planner-validation.mjs";
import { runDependentToolCalls } from "./runner.mjs";
import { createPlannerExecutorAdapter, validatePlannerToolCallInputs } from "./planner-executor-adapter.mjs";
import { buildEvidenceCore } from "../core/evidence.mjs";

/**
 * Validate a complete planner response and dispatch its authorized tool calls.
 *
 * dispatchToolCall receives:
 *   (toolCall, { planId, network, chainId, dependencyResults })
 *
 * No dispatch occurs unless the entire plan passes schema, allowlist, and
 * dependency-graph validation. Tool names are checked again immediately before
 * crossing the host dispatcher boundary.
 */
export async function dispatchValidatedPlannerOutput({
  plannerOutput,
  dispatchToolCall,
  targetPlugin,
  trustedContext = {},
  maxConcurrency = 3
} = {}) {
  const usesBuiltInAdapter = typeof dispatchToolCall !== "function";
  const trustedDispatch = usesBuiltInAdapter
    ? createPlannerExecutorAdapter({ targetPlugin, trustedContext })
    : dispatchToolCall;

  // First gate: JSON Schema + planner tool allowlist.
  validatePlannerOutput(plannerOutput);

  // Snapshot only after successful validation so later caller mutation cannot
  // change the plan while dependency validation or asynchronous dispatch runs.
  const validatedPlan = cloneJsonValue(plannerOutput);
  const dispatchContext = Object.freeze({
    planId: validatedPlan.planId,
    network: validatedPlan.network,
    chainId: validatedPlan.chainId
  });

  // Second gate: verify every tool against the trusted registry before any
  // dispatch, rather than discovering an unauthorized call part-way through.
  for (const [index, call] of validatedPlan.toolCalls.entries()) {
    if (!isKnownPayGuardTool(call.toolName)) {
      const error = new TypeError(
        "Planner call " + index + " is not authorized by the PayGuard tool allowlist."
      );
      error.code = "PLANNER_OUTPUT_TOOL_NOT_ALLOWED";
      throw error;
    }
  }

  // Preflight every built-in tool mapping before the scheduler can dispatch
  // any call. Missing trusted payment/transaction context or invalid tool input
  // therefore rejects the complete plan without partial execution.
  if (usesBuiltInAdapter) {
    validatePlannerToolCallInputs({
      toolCalls: validatedPlan.toolCalls,
      planContext: dispatchContext,
      trustedContext,
      targetPlugin
    });
  }

  const executions = await runDependentToolCalls({
    toolCalls: validatedPlan.toolCalls,
    maxConcurrency,
    dispatchToolCall: async (toolCall, dependencyResults) => {
      // Last-moment gate immediately before the trusted dispatcher is invoked.
      if (!isKnownPayGuardTool(toolCall.toolName)) {
        const error = new TypeError(
          "Tool dispatch denied: tool is not in the PayGuard allowlist."
        );
        error.code = "PLANNER_OUTPUT_TOOL_NOT_ALLOWED";
        throw error;
      }

      return trustedDispatch(
        cloneJsonValue(toolCall),
        Object.freeze({
          ...dispatchContext,
          dependencyResults: cloneJsonValue(dependencyResults)
        })
      );
    }
  });

  return {
    planId: dispatchContext.planId,
    network: dispatchContext.network,
    chainId: dispatchContext.chainId,
    decision: validatedPlan.decision,
    stopReason: validatedPlan.stopReason,
    executions,
    assessment: buildEvidenceCore(executions.map(execution => execution.evidence))
  };
}

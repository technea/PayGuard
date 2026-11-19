/**
 * @module agent/planner-dispatcher
 * @section Validated planner-to-tool dispatch and Evidence Core handoff
 *
 * Accepts untrusted planner output, validates its Draft 2020-12 contract,
 * dispatches only registered PayGuard tools, normalizes their results into
 * evidence records, and delegates the final verdict to Evidence Core.
 *
 * Planner decision fields are orchestration hints only. They are never returned
 * as the security verdict and cannot override the Evidence Core assessment.
 */
import { cloneJsonValue } from "./canonical-json.mjs";
import { isKnownPayGuardTool } from "./tool-catalog.mjs";
import { validatePlannerOutput } from "./planner-validation.mjs";
import { runDependentToolCalls } from "./runner.mjs";
import { createPlannerExecutorAdapter } from "./planner-executor-adapter.mjs";
import { normalizeToolResult } from "./normalize-result.mjs";
import { createErrorEvidence } from "./evidence-record.mjs";
import { buildEvidenceReport } from "./report.mjs";
import { buildEvidenceCore } from "../core/evidence.mjs";

/**
 * Convert bounded dispatcher outcomes into the existing Evidence Core record
 * contract. A failed, blocked, or missing result is never treated as VERIFIED.
 */
function executionsToEvidence(executions, completedAt) {
  return executions.map(execution => {
    const required = true;
    if (execution.status === "COMPLETED") {
      return normalizeToolResult(execution.toolName, execution.result, {
        id: execution.callId,
        checkId: execution.callId,
        required,
        completedAt
      });
    }

    const error = new Error(
      execution.status === "BLOCKED"
        ? "A required dependency did not complete."
        : execution.error || "The tool call did not complete."
    );
    return createErrorEvidence(execution.toolName, error, {
      id: execution.callId,
      checkId: execution.callId,
      required,
      completedAt,
      errorCode: execution.status === "BLOCKED"
        ? "TOOL_DEPENDENCY_BLOCKED"
        : "TOOL_DISPATCH_FAILED"
    });
  });
}

/**
 * Validate a complete planner response and dispatch its authorized tool calls.
 *
 * dispatchToolCall receives:
 *   (toolCall, { planId, network, chainId, dependencyResults })
 *
 * Evidence Core is the sole authority for the final security decision.
 */
export async function dispatchValidatedPlannerOutput({
  plannerOutput,
  dispatchToolCall,
  targetPlugin,
  trustedContext = {},
  maxConcurrency = 3
} = {}) {
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

  const trustedDispatch = typeof dispatchToolCall === "function"
    ? dispatchToolCall
    : createPlannerExecutorAdapter({ targetPlugin, trustedContext });

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

  const completedAt = new Date().toISOString();
  const evidence = executionsToEvidence(executions, completedAt);
  const subject = {
    type: "planner-investigation",
    planId: dispatchContext.planId,
    network: dispatchContext.network,
    chainId: dispatchContext.chainId,
    targets: validatedPlan.toolCalls.map(call => ({
      toolName: call.toolName,
      targetRef: call.targetRef
    }))
  };

  // Evidence Core receives only normalized evidence records and independently
  // derives status, findings, risk score, confidence, and final decision.
  const assessment = buildEvidenceCore(evidence);
  const report = buildEvidenceReport(subject, evidence, {
    investigationId: dispatchContext.planId,
    createdAt: completedAt
  });

  return {
    planId: dispatchContext.planId,
    network: dispatchContext.network,
    chainId: dispatchContext.chainId,
    plannerDisposition: validatedPlan.decision,
    stopReason: validatedPlan.stopReason,
    executions,
    evidence,
    report,
    assessment,
    finalDecision: assessment.decision
  };
}

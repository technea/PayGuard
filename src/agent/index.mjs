/**
 * @module agent
 * @section Public deterministic agent API
 * Exposes evidence, planning, bounded orchestration, correlation, and MCP integration.
 * No model, signing, or transaction execution is included.
 */

export { EVIDENCE_STATUSES, STATUS_PRECEDENCE, EVIDENCE_SCHEMA_VERSION, TOOL_CATALOG } from "./constants.mjs";
export { canonicalJson, cloneJsonValue } from "./canonical-json.mjs";
export { sanitizeUntrustedText, extractUntrustedText } from "./untrusted-data.mjs";
export { normalizeToolStatus, resolveStatus } from "./status.mjs";
export { listAgentCompatibleTools, isKnownPayGuardTool, getToolDefinition } from "./tool-catalog.mjs";
export { createNotCheckedEvidence, createErrorEvidence, createDerivedEvidence } from "./evidence-record.mjs";
export { normalizeToolResult } from "./normalize-result.mjs";
export { aggregateEvidence } from "./aggregate.mjs";
export { buildEvidenceReport } from "./report.mjs";
export { buildAssessmentPlan } from "./plan.mjs";
export { DEFAULT_EXECUTION_LIMITS, validateAssessmentInput, executeAssessmentPlan } from "./execution.mjs";
export { runSecurityAssessment } from "./orchestrator.mjs";
export { correlatePaymentAndTransaction, CORRELATION_SOURCE } from "./correlation.mjs";
export { runInvestigation, runDependentToolCalls } from "./runner.mjs";
export { createPayGuardToolExecutor } from "./payguard-executor.mjs";
export { runPayGuardInvestigation } from "./investigation.mjs";
export { createPayGuardAgentMcpPlugin, startPayGuardAgentMcpServer, PAYGUARD_INVESTIGATION_TOOL } from "./mcp.mjs";
export { validatePlannerOutput, getPlannerOutputSchemaErrors, PlannerOutputValidationError, PLANNER_OUTPUT_SCHEMA } from "./planner-validation.mjs";
export { dispatchValidatedPlannerOutput } from "./planner-dispatcher.mjs";

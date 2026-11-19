/**
 * @module agent/investigation
 * @section Integrated PayGuard investigation entry point
 * Connects explicit bounded tool execution, payment/transaction correlation,
 * strict Evidence Core validation, and the final deterministic report.
 * Tool selection remains caller-controlled; no model or autonomous planner is added.
 */

import { runInvestigation } from "./runner.mjs";
import { createPayGuardToolExecutor } from "./payguard-executor.mjs";
import { correlatePaymentAndTransaction, CORRELATION_SOURCE } from "./correlation.mjs";
import { createDerivedEvidence } from "./evidence-record.mjs";
import { buildEvidenceReport } from "./report.mjs";
import { buildEvidenceCore } from "../core/evidence.mjs";
import plugin from "../plugin.mjs";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function needsCorrelation(input) {
  return isRecord(input) &&
    Object.hasOwn(input, "transaction") &&
    (Object.hasOwn(input, "intent") || Object.hasOwn(input, "paymentRequirements"));
}

function correlationEvidenceRecord(correlation) {
  const record = createDerivedEvidence(CORRELATION_SOURCE, correlation, {
    status: correlation.status,
    reason: correlation.reason,
    required: true
  });

  if (Array.isArray(correlation.checks) && correlation.checks.length > 0) {
    record.evidence = correlation.checks.map(item => ({
      code: item.id,
      severity: item.status === "FAIL" ? "HIGH" : item.status === "UNKNOWN" ? "MEDIUM" : "INFO",
      message: item.detail
    }));
  } else if (correlation.status === "RISK_DETECTED") {
    record.evidence = [{
      code: "PAYMENT_TRANSACTION_CORRELATION_RISK",
      severity: "HIGH",
      message: correlation.reason
    }];
  }

  return record;
}

/**
 * Execute a caller-supplied plan using PayGuard's current read-only tool handlers.
 * When assessmentInput contains transaction plus payment context, append a
 * hash-backed correlation record and validate the complete evidence set through
 * Evidence Core before returning the final report.
 */
export async function runPayGuardInvestigation({
  subject = null,
  checks,
  assessmentInput = null,
  options = {},
  targetPlugin = plugin
} = {}) {
  const correlationRequested = needsCorrelation(assessmentInput);
  if (correlationRequested && Array.isArray(checks) && checks.length >= 32) {
    throw new RangeError("Payment correlation requires one evidence slot; investigations with correlation support at most 31 tool checks.");
  }

  const executeTool = createPayGuardToolExecutor(targetPlugin);
  const initialReport = await runInvestigation({
    subject,
    checks,
    options,
    executeTool
  });

  const records = [...initialReport.evidence];
  let correlation = null;

  if (correlationRequested) {
    const paymentEvidence = records.find(item => item.source === "payguard_check_payment_intent");
    const calldataEvidence = records.find(item => item.source === "payguard_inspect_calldata");
    correlation = correlatePaymentAndTransaction({
      input: assessmentInput,
      paymentEvidence,
      calldataEvidence
    });
    records.push(correlationEvidenceRecord(correlation));
  }

  const report = buildEvidenceReport(subject, records, {
    investigationId: initialReport.investigationId,
    createdAt: initialReport.createdAt
  });
  const assessment = buildEvidenceCore(records);

  return {
    ...report,
    execution: initialReport.execution,
    correlation,
    assessment
  };
}

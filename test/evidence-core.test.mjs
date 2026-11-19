import test from "node:test";
import assert from "node:assert/strict";
import {
  EvidenceCoreSchema,
  buildEvidenceCore,
  createRecommendedAction,
  validateEvidenceCore
} from "../src/core/evidence.mjs";
import {
  createNotCheckedEvidence,
  createEvidence,
  validateEvidence,
  normalizeToolResult
} from "../src/agent/index.mjs";

const tokenTool = "payguard_check_token_security";

test("clean completed inspections allow an empty findings array", () => {
  const record = normalizeToolResult(tokenTool, {
    verdict: "PASS",
    dataStatus: "AVAILABLE",
    findings: []
  });
  const assessment = buildEvidenceCore([record], "VERIFIED");

  assert.equal(assessment.overallStatus, "VERIFIED");
  assert.deepEqual(assessment.findings, []);
  assert.equal(assessment.riskScore, 0);
  assert.equal(assessment.confidence, 1);
  assert.equal(assessment.decision, "ALLOW");
  assert.deepEqual(assessment.recommendedActions, []);
  assert.equal(validateEvidenceCore(assessment), true);
});

test("empty findings with an incomplete required inspection produce WARN, not ALLOW", () => {
  const skipped = createNotCheckedEvidence(tokenTool);
  const assessment = buildEvidenceCore([skipped], "NOT_CHECKED");

  assert.deepEqual(assessment.findings, []);
  assert.equal(assessment.decision, "WARN");
  assert.equal(assessment.confidence, 0);
  assert.equal(assessment.recommendedActions[0].executionMode, "READ_ONLY_RECOMMENDATION");
  assert.equal(assessment.recommendedActions[0].requiresUserApproval, true);
});

test("unavailable required evidence cannot become ALLOW", () => {
  const unavailable = normalizeToolResult(tokenTool, {
    verdict: "UNVERIFIED",
    dataStatus: "UNAVAILABLE",
    findings: []
  });
  const assessment = buildEvidenceCore([unavailable], "UNVERIFIED");

  assert.equal(assessment.decision, "WARN");
  assert.equal(assessment.confidence, 0);
  assert.equal(assessment.recommendedActions.length, 1);
});

test("risk findings are normalized into the restricted category and severity vocabularies", () => {
  const record = normalizeToolResult("payguard_inspect_calldata", {
    verdict: "BLOCK",
    findings: [{
      code: "UNLIMITED_ALLOWANCE_UINT256_MAX",
      severity: "critical",
      message: "Unlimited token allowance detected."
    }]
  });
  const assessment = buildEvidenceCore([record], "RISK_DETECTED");

  assert.equal(assessment.findings.length, 1);
  assert.equal(assessment.findings[0].ruleId, "UNLIMITED_ALLOWANCE_UINT256_MAX");
  assert.equal(assessment.findings[0].category, "APPROVAL");
  assert.equal(assessment.findings[0].severity, "CRITICAL");
  assert.equal(assessment.decision, "REVOKE_APPROVAL");
  assert.equal(assessment.riskScore, 90);
});

test("risk scoring and decisions are deterministic", () => {
  const record = normalizeToolResult(tokenTool, {
    verdict: "REVIEW",
    dataStatus: "AVAILABLE",
    findings: [
      { code: "OWNER_PRIVILEGE", severity: "high" },
      { code: "TRANSFER_RESTRICTION", severity: "medium" }
    ]
  });

  const first = buildEvidenceCore([record], "RISK_DETECTED");
  const second = buildEvidenceCore([record], "RISK_DETECTED");

  assert.deepEqual(first, second);
  assert.equal(first.riskScore, 75);
  assert.equal(first.decision, "BLOCK");
});

test("schema rejects invalid ruleId, category, severity and decision values", () => {
  const valid = {
    riskScore: 40,
    confidence: 1,
    decision: "WARN",
    findings: [{
      ruleId: "TOKEN_RISK",
      category: "REPUTATION",
      severity: "MEDIUM",
      description: "A risk signal was detected.",
      metadata: { source: tokenTool, evidenceId: "evidence-1" }
    }],
    recommendedActions: [{
      decision: "WARN",
      action: "Pause and review.",
      reason: "A risk signal needs manual review.",
      evidenceRefs: [],
      executionMode: "READ_ONLY_RECOMMENDATION",
      requiresUserApproval: true
    }],
    overallStatus: "RISK_DETECTED",
    evidenceCoverage: [{ evidenceId: "evidence-1", status: "RISK_DETECTED", required: true }]
  };

  assert.equal(EvidenceCoreSchema.safeParse(valid).success, true);

  for (const [key, value] of [
    ["ruleId", ""],
    ["category", "PAYMENT"],
    ["severity", "SEVERE"]
  ]) {
    const invalid = structuredClone(valid);
    invalid.findings[0][key] = value;
    assert.equal(validateEvidenceCore(invalid), false);
    assert.throws(() => EvidenceCoreSchema.parse(invalid));
  }

  const invalidDecision = structuredClone(valid);
  invalidDecision.decision = "EXECUTE_TRANSACTION";
  assert.equal(validateEvidenceCore(invalidDecision), false);
});

test("schema rejects unknown properties and malformed recommendation payloads", () => {
  const valid = {
    riskScore: 0,
    confidence: 1,
    decision: "ALLOW",
    findings: [],
    recommendedActions: [],
    overallStatus: "VERIFIED",
    evidenceCoverage: [{ evidenceId: "verified-1", status: "VERIFIED", required: true }]
  };

  assert.equal(validateEvidenceCore({ ...valid, autonomousExecution: true }), false);
  assert.equal(validateEvidenceCore({ ...valid, recommendedActions: [{
    decision: "BLOCK",
    action: "Block transaction",
    reason: "Risk",
    evidenceRefs: [],
    executionMode: "EXECUTE",
    requiresUserApproval: false
  }] }), false);
});

test("approval revocation and safe-vault redirection are recommendation-only types", () => {
  const revoke = createRecommendedAction({
    decision: "REVOKE_APPROVAL",
    action: "Review and revoke the allowance in a trusted wallet.",
    reason: "An approval risk was detected."
  });
  const redirect = createRecommendedAction({
    decision: "REDIRECT_SAFE_VAULT",
    action: "Only use a destination independently verified by the user.",
    reason: "A user-controlled recovery workflow may be appropriate."
  });

  assert.equal(revoke.executionMode, "READ_ONLY_RECOMMENDATION");
  assert.equal(redirect.executionMode, "READ_ONLY_RECOMMENDATION");
  assert.equal(revoke.requiresUserApproval, true);
  assert.equal(redirect.requiresUserApproval, true);
});


test("legacy Evidence Core constructor and validator remain backward-compatible", () => {
  const evidence = createEvidence({
    sourceModule: "token-security",
    target: { type: "token", identifier: "0xabc" },
    status: "VERIFIED",
    findings: [],
    metadata: { riskScore: 0, confidence: 1 }
  });

  assert.equal(validateEvidence(evidence), true);
  assert.equal(validateEvidence({ ...evidence, status: "EXECUTED" }), false);
  assert.equal(validateEvidence({ ...evidence, timestamp: "not-a-date" }), false);
});


test("caller-supplied VERIFIED cannot manufacture ALLOW from zero evidence records", () => {
  assert.throws(() => buildEvidenceCore([], "VERIFIED"), /does not match the evidence records/);
  const assessment = buildEvidenceCore([], "NOT_CHECKED");
  assert.equal(assessment.decision, "WARN");
  assert.equal(assessment.confidence, 0);
  assert.equal(assessment.overallStatus, "NOT_CHECKED");
  assert.equal(validateEvidenceCore(assessment), true);
});

test("validator rejects ALLOW with findings, zero confidence, or no evidence coverage", () => {
  const valid = buildEvidenceCore([normalizeToolResult(tokenTool, {
    verdict: "PASS",
    dataStatus: "AVAILABLE",
    findings: []
  })], "VERIFIED");
  assert.equal(valid.decision, "ALLOW");

  assert.equal(validateEvidenceCore({
    ...valid,
    findings: [{
      ruleId: "TOKEN_RISK",
      category: "REPUTATION",
      severity: "MEDIUM",
      description: "A risk signal was detected.",
      metadata: { source: tokenTool, evidenceId: "verified-1" }
    }]
  }), false);
  assert.equal(validateEvidenceCore({ ...valid, confidence: 0 }), false);
  assert.equal(validateEvidenceCore({ ...valid, evidenceCoverage: [] }), false);
});

test("validator rejects ALLOW when required evidence is incomplete, unavailable, or errored", () => {
  for (const status of ["NOT_CHECKED", "PENDING", "UNVERIFIED", "ERROR", "RISK_DETECTED"]) {
    const forged = {
      riskScore: 0,
      confidence: status === "RISK_DETECTED" ? 1 : 0,
      decision: "ALLOW",
      findings: [],
      recommendedActions: [],
      overallStatus: status,
      evidenceCoverage: [{ evidenceId: "required-1", status, required: true }]
    };
    assert.equal(validateEvidenceCore(forged), false, `status ${status} must not allow`);
  }
});

test("builder rejects malformed evidence records and mismatched caller status", () => {
  assert.throws(() => buildEvidenceCore([{ id: "missing-status" }], "VERIFIED"));
  assert.throws(() => buildEvidenceCore([{
    id: "unknown-status",
    status: "SAFE"
  }], "VERIFIED"));
  assert.throws(() => buildEvidenceCore([{
    id: "valid-record",
    status: "UNVERIFIED"
  }], "VERIFIED"));
});


test("assessment validator rejects unsupported safe-vault decisions and mismatched evidence references", () => {
  const record = normalizeToolResult(tokenTool, {
    verdict: "REVIEW",
    dataStatus: "AVAILABLE",
    findings: [{ code: "TOKEN_REVIEW", severity: "medium", message: "Manual review required." }]
  });
  const valid = buildEvidenceCore([record], "RISK_DETECTED");
  assert.equal(validateEvidenceCore(valid), true);

  const forgedDecision = structuredClone(valid);
  forgedDecision.decision = "REDIRECT_SAFE_VAULT";
  forgedDecision.recommendedActions[0].decision = "REDIRECT_SAFE_VAULT";
  assert.equal(validateEvidenceCore(forgedDecision), false);

  const forgedReference = structuredClone(valid);
  forgedReference.recommendedActions[0].evidenceRefs = ["not-in-evidence-coverage"];
  assert.equal(validateEvidenceCore(forgedReference), false);

  const duplicateReference = structuredClone(valid);
  duplicateReference.recommendedActions[0].evidenceRefs = [
    duplicateReference.evidenceCoverage[0].evidenceId,
    duplicateReference.evidenceCoverage[0].evidenceId
  ];
  assert.equal(validateEvidenceCore(duplicateReference), false);
});


test("validator rejects findings that reference evidence outside the assessment coverage", () => {
  const record = normalizeToolResult(tokenTool, {
    verdict: "REVIEW",
    dataStatus: "AVAILABLE",
    findings: [{ code: "TOKEN_REVIEW", severity: "medium", message: "Manual review required." }]
  });
  const assessment = buildEvidenceCore([record], "RISK_DETECTED");
  const forged = structuredClone(assessment);
  forged.findings[0].metadata.evidenceId = "unknown-evidence";
  assert.equal(validateEvidenceCore(forged), false);
});

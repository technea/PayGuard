import test from "node:test";
import assert from "node:assert/strict";
import { normalizeToolResult, normalizeToolStatus } from "../src/agent/index.mjs";
import { buildEvidenceCore } from "../src/core/evidence.mjs";

const tools = [
  "payguard_check_payment_intent",
  "payguard_analyze_url",
  "payguard_prepare_threat_report",
  "payguard_inspect_calldata",
  "payguard_check_token_security",
  "payguard_check_address_security",
  "payguard_scan_wallet_tokens"
];

test("all seven tool families fail closed on inconclusive or partial outputs", () => {
  const cases = [
    [tools[0], { status: "REVIEW" }],
    [tools[1], { verdict: "NO_KNOWN_THREAT" }],
    [tools[2], { verdict: "UNVERIFIED", reportStatus: "DRAFT_NOT_SUBMITTED" }],
    [tools[3], { verdict: "UNKNOWN" }],
    [tools[4], { verdict: "UNVERIFIED", dataStatus: "UNAVAILABLE" }],
    [tools[5], { verdict: "UNVERIFIED", dataStatus: "INCOMPLETE" }],
    [tools[6], { status: "SUCCESS", scanCompletionStatus: "PARTIAL", discoveryMode: "REGISTRY_AND_CUSTOM_PARTIAL", tokens: [], summary: { unverifiedCount: 0 } }]
  ];
  for (const [tool, output] of cases) {
    assert.equal(normalizeToolStatus(tool, output).status, "UNVERIFIED", tool);
  }
});

test("wallet token severity and target metadata survive normalization into Evidence Core", () => {
  const record = normalizeToolResult(tools[6], {
    status: "SUCCESS",
    scanCompletionStatus: "COMPLETE",
    discoveryMode: "ALCHEMY_INDEXER",
    walletAddress: "0x1111111111111111111111111111111111111111",
    tokens: [{
      contractAddress: "0x2222222222222222222222222222222222222222",
      tokenName: "Suspicious Token",
      tokenSymbol: "BAD",
      verdict: "BLOCK",
      riskLevel: "CRITICAL",
      isImpersonation: true,
      reason: "Impersonates an official asset",
      findings: [{ code: "goplus_honeypot", severity: "critical", message: "Token sell simulation failed." }]
    }],
    summary: { highRiskCount: 1, suspiciousCount: 0, unverifiedCount: 0 }
  });
  assert.equal(record.status, "RISK_DETECTED");
  assert.ok(record.evidence.some(item => item.severity === "CRITICAL"));
  assert.ok(record.evidence.some(item => item.code === "goplus_honeypot"));
  const assessment = buildEvidenceCore([record]);
  assert.equal(assessment.decision, "BLOCK");
  assert.ok(assessment.findings.some(f => f.severity === "CRITICAL"));
  assert.ok(assessment.findings.some(f => f.metadata.affectedTarget === "0x2222222222222222222222222222222222222222"));
});

test("lowercase payment and calldata failure checks are retained as findings", () => {
  const payment = normalizeToolResult(tools[0], {
    status: "BLOCK",
    summary: "Every payment option violates policy.",
    checks: [{ id: "recipient_policy", status: "fail", detail: "Recipient is not allowed." }]
  });
  assert.equal(payment.status, "RISK_DETECTED");
  assert.ok(payment.evidence.some(item => item.code === "recipient_policy"));
  const calldata = normalizeToolResult(tools[3], {
    verdict: "BLOCK",
    riskLevel: "CRITICAL",
    checks: [{ id: "unlimited_approval", status: "FAIL", severity: "CRITICAL", detail: "Unlimited approval." }]
  });
  assert.ok(calldata.evidence.some(item => item.severity === "CRITICAL"));
});

test("source BLOCK without itemized findings retains explicit high severity", () => {
  const record = normalizeToolResult(tools[0], { status: "BLOCK", summary: "Explicit policy block." });
  assert.equal(record.evidence[0].severity, "HIGH");
  const assessment = buildEvidenceCore([record]);
  assert.equal(assessment.decision, "BLOCK");
});

test("skipped dependency calls are explicitly marked NOT_CHECKED for evidence mapping", async () => {
  const { runDependentToolCalls } = await import("../src/agent/runner.mjs");
  const result = await runDependentToolCalls({
    toolCalls: [
      { callId: "a", toolName: tools[1], dependsOn: [] },
      { callId: "b", toolName: tools[2], dependsOn: ["a"] }
    ],
    dispatchToolCall: async () => { throw new Error("simulated dispatch failure"); }
  });
  assert.equal(result[0].evidenceStatus, "ERROR");
  assert.equal(result[0].evidence.status, "ERROR");
  assert.equal(result[1].status, "BLOCKED");
  assert.equal(result[1].evidenceStatus, "NOT_CHECKED");
  assert.equal(result[1].evidence.status, "NOT_CHECKED");
});

test("wallet scanner's actual Blockscout complete shape is VERIFIED when no risks or unknown holdings exist", () => {
  const record = normalizeToolResult(tools[6], {
    status: "SUCCESS",
    scanCompletionStatus: "COMPLETE",
    discoveryMode: "BLOCKSCOUT_INDEXER",
    tokens: [{ contractAddress: "0x3333333333333333333333333333333333333333", securityStatus: "NO KNOWN ISSUES FOUND", verdict: "PASS", riskLevel: "LOW" }],
    summary: { totalTokensScanned: 1, highRiskCount: 0, suspiciousCount: 0, cleanCount: 1, unverifiedCount: 0 }
  });
  assert.equal(record.status, "VERIFIED");
});

test("mixed payment alternatives with a failing policy check retain risk evidence", () => {
  const record = normalizeToolResult(tools[0], {
    status: "REVIEW",
    summary: "Payment options are mixed.",
    checks: [
      { id: "candidate", status: "block", detail: "Payment option 0: BLOCK." },
      { id: "recipient", status: "fail", detail: "Recipient does not match the trusted allowlist." },
      { id: "scheme", status: "unknown", detail: "Payment scheme is missing." }
    ]
  });
  assert.equal(record.status, "RISK_DETECTED");
  assert.ok(record.evidence.some(item => item.code === "recipient" && item.severity === "HIGH"));
  assert.equal(buildEvidenceCore([record]).decision, "BLOCK");
});

test("risk verdicts from all seven actual tool output families reach Evidence Core", () => {
  const outputs = [
    [tools[0], { status: "BLOCK", summary: "All payment candidates violate policy.", checks: [{ id: "recipient", status: "fail", detail: "Recipient is not allowlisted." }] }, "BLOCK"],
    [tools[1], { verdict: "SUSPICIOUS", riskLevel: "HIGH", checks: [{ id: "base_ecosystem_impersonation", severity: "high", status: "fail", detail: "Base lookalike domain." }] }, "BLOCK"],
    [tools[2], { verdict: "KNOWN_MALICIOUS", riskLevel: "CRITICAL", findings: [{ id: "threat_intelligence_match", severity: "critical", status: "fail", detail: "Threat intelligence match." }] }, "BLOCK"],
    [tools[3], { verdict: "BLOCK", riskLevel: "CRITICAL", reasons: ["UNLIMITED_ALLOWANCE_UINT256_MAX"], checks: [{ id: "unlimited_allowance", status: "FAIL", detail: "Unlimited token approval." }] }, "BLOCK"],
    [tools[4], { verdict: "BLOCK", riskLevel: "CRITICAL", dataStatus: "AVAILABLE", contractAddress: "0x4444444444444444444444444444444444444444", findings: [{ code: "HONEYPOT", severity: "critical", message: "Sell transactions are blocked." }] }, "BLOCK"],
    [tools[5], { verdict: "REVIEW", riskLevel: "MEDIUM", dataStatus: "AVAILABLE", address: "0x5555555555555555555555555555555555555555", findings: [{ code: "PHISHING_RELATED", severity: "medium", message: "Address is associated with phishing reports." }] }, "WARN"],
    [tools[6], { status: "SUCCESS", scanCompletionStatus: "COMPLETE", discoveryMode: "ALCHEMY_INDEXER", summary: { highRiskCount: 1, suspiciousCount: 0, unverifiedCount: 0 }, tokens: [{ name: "Malicious", symbol: "BAD", contractAddress: "0x6666666666666666666666666666666666666666", securityStatus: "HIGH RISK", verdict: "BLOCK", riskLevel: "CRITICAL", findings: [{ code: "HONEYPOT", severity: "critical", message: "Sell blocked." }] }] }, "BLOCK"]
  ];
  for (const [tool, output, expectedDecision] of outputs) {
    const record = normalizeToolResult(tool, output);
    assert.equal(record.status, "RISK_DETECTED", tool);
    assert.ok(record.evidence.length > 0, tool);
    const assessment = buildEvidenceCore([record]);
    assert.equal(assessment.decision, expectedDecision, tool);
    assert.ok(assessment.findings.length > 0, tool);
  }
});

test("risk verdict without itemized findings is converted into a safe fallback finding", () => {
  const record = normalizeToolResult(tools[1], {
    verdict: "SUSPICIOUS",
    riskLevel: "HIGH",
    summary: "Suspicious URL result."
  });
  assert.equal(record.status, "RISK_DETECTED");
  assert.equal(record.evidence.length, 0);
  const assessment = buildEvidenceCore([record]);
  assert.equal(assessment.decision, "BLOCK");
  assert.equal(assessment.findings[0].severity, "HIGH");
});

test("wallet high-risk securityStatus is not masked by a non-risk verdict field", () => {
  const record = normalizeToolResult(tools[6], {
    status: "SUCCESS",
    scanCompletionStatus: "COMPLETE",
    discoveryMode: "BLOCKSCOUT_INDEXER",
    summary: { highRiskCount: 1, suspiciousCount: 0, unverifiedCount: 0 },
    tokens: [{
      contractAddress: "0x7777777777777777777777777777777777777777",
      verdict: "UNVERIFIED",
      securityStatus: "HIGH RISK",
      riskLevel: "UNKNOWN",
      isImpersonation: false
    }]
  });
  assert.equal(record.status, "RISK_DETECTED");
  assert.equal(record.evidence[0].severity, "HIGH");
  assert.equal(buildEvidenceCore([record]).decision, "BLOCK");
});

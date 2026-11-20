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
    [tools[6], { status: "SUCCESS", discoveryMode: "REGISTRY_AND_CUSTOM_PARTIAL", tokens: [], summary: { unverifiedCount: 1 } }]
  ];
  for (const [tool, output] of cases) {
    assert.equal(normalizeToolStatus(tool, output).status, "UNVERIFIED", tool);
  }
});

test("wallet token severity and target metadata survive normalization into Evidence Core", () => {
  const record = normalizeToolResult(tools[6], {
    status: "SUCCESS",
    discoveryMode: "FULL_INDEXER",
    walletAddress: "0x1111111111111111111111111111111111111111",
    tokens: [{
      contractAddress: "0x2222222222222222222222222222222222222222",
      tokenName: "Suspicious Token",
      tokenSymbol: "BAD",
      verdict: "BLOCK",
      riskLevel: "CRITICAL",
      isImpersonation: true,
      reason: "Impersonates an official asset"
    }],
    summary: { highRiskCount: 1, suspiciousCount: 0, unverifiedCount: 0 }
  });
  assert.equal(record.status, "RISK_DETECTED");
  assert.ok(record.evidence.some(item => item.severity === "CRITICAL"));
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
  assert.equal(result[1].status, "BLOCKED");
  assert.equal(result[1].evidenceStatus, "NOT_CHECKED");
});

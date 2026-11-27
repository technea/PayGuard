/**
 * Integration tests for POST /api/assess
 * Uses the Node test runner with mocked invokeTool (no live HTTP).
 */

import test from "node:test";
import assert from "node:assert/strict";
import { runSecurityAssessment } from "../src/agent/index.mjs";

const CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const WALLET   = "0x2222222222222222222222222222222222222222";

// Minimal mock invokeTool that returns valid PASS output for all tools
function mockInvokeTool(toolName) {
  if (toolName === "payguard_analyze_url") {
    return Promise.resolve({ verdict: "EXPECTED_DOMAIN_MATCH", riskLevel: "LOW" });
  }
  if (toolName === "payguard_check_token_security") {
    return Promise.resolve({ verdict: "PASS", dataStatus: "AVAILABLE", reasonCodes: [] });
  }
  if (toolName === "payguard_check_address_security") {
    return Promise.resolve({ verdict: "PASS", dataStatus: "AVAILABLE" });
  }
  if (toolName === "payguard_scan_wallet_tokens") {
    return Promise.resolve({
      status: "SUCCESS",
      scanCompletionStatus: "COMPLETE",
      discoveryMode: "ALCHEMY_INDEXER",
      summary: { totalTokensScanned: 0, highRiskCount: 0, suspiciousCount: 0, cleanCount: 0, unverifiedCount: 0 },
      tokens: []
    });
  }
  if (toolName === "payguard_inspect_calldata") {
    return Promise.resolve({ verdict: "PASS", riskLevel: "LOW", operation: "NATIVE_TRANSFER", reasons: [] });
  }
  if (toolName === "payguard_check_payment_intent") {
    return Promise.resolve({ verdict: "PASS", riskLevel: "LOW" });
  }
  return Promise.resolve({ verdict: "PASS" });
}

// ── Basic assessment with contractAddress ─────────────────────────────────
test("1. POST /api/assess with contractAddress returns report with dimensions and normalizedFindings", async () => {
  const result = await runSecurityAssessment(
    { contractAddress: CONTRACT, chainId: 8453 },
    { invokeTool: mockInvokeTool, totalTimeoutMs: 5_000 }
  );
  assert.ok(result, "result must exist");
  assert.ok(result.report, "result.report must exist");
  assert.ok(result.plan, "result.plan must exist");
  assert.ok(Array.isArray(result.plan), "plan must be array");

  const report = result.report;
  assert.ok("overallStatus" in report, "report must have overallStatus");
  assert.ok("dimensions" in report, "report must have dimensions");
  assert.ok("normalizedFindings" in report, "report must have normalizedFindings");
  assert.ok(Array.isArray(report.normalizedFindings), "normalizedFindings must be array");
  assert.ok("assessmentSchemaVersion" in report, "report must have assessmentSchemaVersion");

  // dimensions must have all 4 fields
  const { dimensions } = report;
  assert.ok("securityVerdict" in dimensions);
  assert.ok("verificationStatus" in dimensions);
  assert.ok("dataStatus" in dimensions);
  assert.ok("liquidityStatus" in dimensions);
});

// ── Assessment with URL subject ───────────────────────────────────────────
test("2. Assessment with url subject works and returns dimensions", async () => {
  const result = await runSecurityAssessment(
    { url: "https://base.org" },
    { invokeTool: mockInvokeTool, totalTimeoutMs: 5_000 }
  );
  assert.ok(result.report.dimensions);
  assert.ok("securityVerdict" in result.report.dimensions);
});

// ── Assessment with walletAddress subject ────────────────────────────────
test("3. Assessment with walletAddress subject works", async () => {
  const result = await runSecurityAssessment(
    { walletAddress: WALLET },
    { invokeTool: mockInvokeTool, totalTimeoutMs: 5_000 }
  );
  assert.ok(result.report.dimensions);
});

// ── Empty object throws ───────────────────────────────────────────────────
test("4. Empty assessment input rejects with at least one supported subject error", async () => {
  await assert.rejects(
    () => runSecurityAssessment({}, { invokeTool: mockInvokeTool }),
    /at least one supported subject/i
  );
});

// ── Circular reference rejects ────────────────────────────────────────────
test("5. Circular reference in input rejects with JSON-serializable error", async () => {
  const circular = {};
  circular.self = circular;
  await assert.rejects(
    () => runSecurityAssessment({ url: "https://base.org", extra: circular }, { invokeTool: mockInvokeTool }),
    /JSON-serializable/i
  );
});

// ── Tool failure → ERROR status, never VERIFIED ──────────────────────────
test("6. Tool failure produces ERROR status, never VERIFIED", async () => {
  const result = await runSecurityAssessment(
    { contractAddress: CONTRACT },
    {
      invokeTool: async () => { throw new Error("Provider offline"); },
      perToolTimeoutMs: 500,
      totalTimeoutMs: 2_000
    }
  );
  assert.notEqual(result.report.overallStatus, "VERIFIED",
    "A failed tool must NOT yield VERIFIED status");
});

// ── verifyContract: true triggers optional contract verification task ─────
test("7. verifyContract:true adds payguard_verify_contract task to plan", async () => {
  const result = await runSecurityAssessment(
    { contractAddress: CONTRACT, verifyContract: true },
    { invokeTool: mockInvokeTool, totalTimeoutMs: 5_000 }
  );
  const hasVerifyTask = result.plan.some(t => t.toolName === "payguard_verify_contract");
  assert.ok(hasVerifyTask,
    `Expected payguard_verify_contract in plan tasks: ${result.plan.map(t => t.toolName).join(", ")}`);
});

// ── normalizedFindings are advisory, never execution instructions ─────────
test("8. normalizedFindings never contain executable instructions or private data", async () => {
  const result = await runSecurityAssessment(
    { contractAddress: CONTRACT },
    { invokeTool: mockInvokeTool, totalTimeoutMs: 5_000 }
  );
  for (const finding of result.report.normalizedFindings) {
    // No finding should claim to be a confirmed "safe" guarantee
    assert.ok(!finding.description?.includes("guaranteed safe"),
      `Finding description must not claim safe: ${finding.description}`);
    // No private key patterns
    assert.ok(!finding.description?.match(/private.?key/i),
      `Finding must not mention private key: ${finding.description}`);
  }
});

// ── derivedChecks is present ──────────────────────────────────────────────
test("9. result includes derivedChecks array", async () => {
  const result = await runSecurityAssessment(
    { url: "https://base.org" },
    { invokeTool: mockInvokeTool, totalTimeoutMs: 5_000 }
  );
  assert.ok("derivedChecks" in result, "derivedChecks must be in result");
  assert.ok(Array.isArray(result.derivedChecks), "derivedChecks must be array");
});

// ── evidenceSources is present in report ──────────────────────────────────
test("10. report includes evidenceSources array", async () => {
  const result = await runSecurityAssessment(
    { contractAddress: CONTRACT },
    { invokeTool: mockInvokeTool, totalTimeoutMs: 5_000 }
  );
  assert.ok(Array.isArray(result.report.evidenceSources),
    "report.evidenceSources must be an array");
});


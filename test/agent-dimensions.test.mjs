/**
 * Tests for src/agent/dimensions.mjs
 * - deriveSecurityDimensions
 * - buildNormalizedFindings
 * - validateSecurityAssessment
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  deriveSecurityDimensions,
  buildNormalizedFindings,
  validateSecurityAssessment,
  SECURITY_ASSESSMENT_SCHEMA_VERSION,
  SECURITY_VERDICTS,
  VERIFICATION_STATUSES,
  DATA_STATUSES,
  LIQUIDITY_STATUSES
} from "../src/agent/dimensions.mjs";

// ── Constant enumerations ─────────────────────────────────────────────────
test("1. Constant enumerations are frozen arrays with expected members", () => {
  assert.ok(Object.isFrozen(SECURITY_VERDICTS));
  assert.ok(SECURITY_VERDICTS.includes("PASS"));
  assert.ok(SECURITY_VERDICTS.includes("BLOCK"));
  assert.ok(SECURITY_VERDICTS.includes("UNKNOWN"));

  assert.ok(Object.isFrozen(VERIFICATION_STATUSES));
  assert.ok(VERIFICATION_STATUSES.includes("VERIFIED"));
  assert.ok(VERIFICATION_STATUSES.includes("UNVERIFIED"));
  assert.ok(VERIFICATION_STATUSES.includes("NOT_CHECKED"));

  assert.ok(Object.isFrozen(DATA_STATUSES));
  assert.ok(DATA_STATUSES.includes("FRESH"));
  assert.ok(DATA_STATUSES.includes("STALE"));
  assert.ok(DATA_STATUSES.includes("UNAVAILABLE"));

  assert.ok(Object.isFrozen(LIQUIDITY_STATUSES));
  assert.ok(LIQUIDITY_STATUSES.includes("ZERO"));
  assert.ok(LIQUIDITY_STATUSES.includes("HEALTHY"));
});

// ── Empty records ─────────────────────────────────────────────────────────
test("2. Empty records array returns safe defaults (all UNKNOWN/NOT_CHECKED/UNAVAILABLE)", () => {
  const dims = deriveSecurityDimensions([]);
  assert.equal(dims.securityVerdict, "UNKNOWN");
  assert.equal(dims.verificationStatus, "NOT_CHECKED");
  assert.equal(dims.dataStatus, "UNAVAILABLE");
  assert.equal(dims.liquidityStatus, "UNKNOWN");
});

test("3. Null or non-array input returns safe defaults", () => {
  const dims1 = deriveSecurityDimensions(null);
  const dims2 = deriveSecurityDimensions("bad");
  assert.equal(dims1.securityVerdict, "UNKNOWN");
  assert.equal(dims2.securityVerdict, "UNKNOWN");
});

// ── CRITICAL: NO_DEX_LIQUIDITY never escalates securityVerdict ───────────
test("4. NO_DEX_LIQUIDITY finding sets liquidityStatus ZERO but NOT securityVerdict BLOCK", () => {
  const records = [{
    id: "token-1",
    source: "payguard_check_token_security",
    status: "RISK_DETECTED",
    reason: "NO_DEX_LIQUIDITY",
    rawOutput: {
      verdict: "REVIEW",
      dataStatus: "AVAILABLE",
      reasonCodes: ["NO_DEX_LIQUIDITY"]
    },
    evidence: [{ code: "NO_DEX_LIQUIDITY", severity: "LOW", message: "No DEX liquidity" }]
  }];
  const dims = deriveSecurityDimensions(records);
  assert.equal(dims.liquidityStatus, "ZERO");
  assert.notEqual(dims.securityVerdict, "BLOCK",
    "NO_DEX_LIQUIDITY alone must NEVER produce securityVerdict BLOCK");
  assert.notEqual(dims.securityVerdict, "CAUTION",
    "NO_DEX_LIQUIDITY alone must NEVER produce securityVerdict CAUTION");
});

// ── GoPlus PASS + Sourcify UNVERIFIED ─────────────────────────────────────
test("5. GoPlus PASS + verify contract UNVERIFIED: securityVerdict PASS, verificationStatus UNVERIFIED", () => {
  const records = [
    {
      id: "token-1",
      source: "payguard_check_token_security",
      status: "VERIFIED",
      rawOutput: {
        verdict: "PASS",
        dataStatus: "AVAILABLE",
        reasonCodes: ["CLOSED_SOURCE_BYTECODE"]
      },
      evidence: []
    },
    {
      id: "verify-1",
      source: "payguard_verify_contract",
      status: "UNVERIFIED",
      rawOutput: {
        verificationStatus: "UNVERIFIED",
        dataStatus: "AVAILABLE"
      },
      evidence: []
    }
  ];
  const dims = deriveSecurityDimensions(records);
  assert.equal(dims.verificationStatus, "UNVERIFIED");
  assert.notEqual(dims.securityVerdict, "BLOCK",
    "Unverified source code alone must NOT produce securityVerdict BLOCK");
});

// ── GoPlus BLOCK → securityVerdict BLOCK ──────────────────────────────────
test("6. GoPlus BLOCK verdict produces securityVerdict BLOCK", () => {
  const records = [{
    id: "token-1",
    source: "payguard_check_token_security",
    status: "RISK_DETECTED",
    rawOutput: { verdict: "BLOCK", dataStatus: "AVAILABLE", reasonCodes: ["IS_HONEYPOT"] },
    evidence: [{ code: "IS_HONEYPOT", severity: "HIGH", message: "Token is a honeypot." }]
  }];
  const dims = deriveSecurityDimensions(records);
  assert.equal(dims.securityVerdict, "BLOCK");
});

// ── All ERROR/NOT_CHECKED → securityVerdict UNKNOWN ──────────────────────
test("7. All ERROR and NOT_CHECKED records produce securityVerdict UNKNOWN", () => {
  const records = [
    { id: "1", source: "payguard_check_token_security", status: "ERROR", rawOutput: {}, evidence: [] },
    { id: "2", source: "payguard_analyze_url", status: "NOT_CHECKED", rawOutput: {}, evidence: [] }
  ];
  const dims = deriveSecurityDimensions(records);
  assert.equal(dims.securityVerdict, "UNKNOWN");
});

// ── All VERIFIED → securityVerdict PASS ──────────────────────────────────
test("8. All VERIFIED records with fresh data produce securityVerdict PASS", () => {
  const records = [
    {
      id: "1",
      source: "payguard_check_token_security",
      status: "VERIFIED",
      rawOutput: { verdict: "PASS", dataStatus: "AVAILABLE", reasonCodes: [] },
      evidence: []
    },
    {
      id: "2",
      source: "payguard_analyze_url",
      status: "VERIFIED",
      rawOutput: { verdict: "EXPECTED_DOMAIN_MATCH", dataStatus: "AVAILABLE" },
      evidence: []
    }
  ];
  const dims = deriveSecurityDimensions(records);
  assert.equal(dims.securityVerdict, "PASS");
  assert.equal(dims.dataStatus, "FRESH");
});

// ── buildNormalizedFindings ───────────────────────────────────────────────
test("9. buildNormalizedFindings produces 10-field objects", () => {
  const records = [{
    id: "token-1",
    source: "payguard_check_token_security",
    status: "RISK_DETECTED",
    reason: "IS_HONEYPOT",
    rawOutput: { verdict: "BLOCK", provider: "goplus" },
    completedAt: new Date().toISOString(),
    evidence: [{ code: "IS_HONEYPOT", severity: "HIGH", message: "Token is a honeypot." }]
  }];
  const findings = buildNormalizedFindings(records);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.ok(typeof f.id === "string", "id must be string");
  assert.ok(typeof f.category === "string", "category must be string");
  assert.ok(typeof f.severity === "string", "severity must be string");
  assert.ok(typeof f.status === "string", "status must be string");
  assert.ok(typeof f.description === "string", "description must be string");
  assert.ok("evidence" in f, "evidence must be present");
  assert.ok(typeof f.source === "string", "source must be string");
  assert.ok(typeof f.method === "string", "method must be string");
  assert.ok(typeof f.timestamp === "string", "timestamp must be string");
  assert.ok(typeof f.recommendedAction === "string", "recommendedAction must be string");
});

test("10. NO_DEX_LIQUIDITY finding is INFORMATIONAL severity in normalized findings", () => {
  const records = [{
    id: "token-1",
    source: "payguard_check_token_security",
    status: "RISK_DETECTED",
    rawOutput: { verdict: "REVIEW", dataStatus: "AVAILABLE", reasonCodes: ["NO_DEX_LIQUIDITY"] },
    completedAt: new Date().toISOString(),
    evidence: [{ code: "NO_DEX_LIQUIDITY", severity: "LOW", message: "No DEX liquidity found." }]
  }];
  const findings = buildNormalizedFindings(records);
  assert.ok(findings.length > 0);
  const liquidityFinding = findings.find(f => f.id.includes("NO_DEX_LIQUIDITY"));
  assert.ok(liquidityFinding, "Must find a NO_DEX_LIQUIDITY finding");
  assert.equal(liquidityFinding.severity, "INFORMATIONAL",
    "NO_DEX_LIQUIDITY must always be INFORMATIONAL severity");
});

test("11. buildNormalizedFindings with empty records returns empty array", () => {
  assert.deepEqual(buildNormalizedFindings([]), []);
  assert.deepEqual(buildNormalizedFindings(null), []);
  assert.deepEqual(buildNormalizedFindings("bad"), []);
});

// ── validateSecurityAssessment ────────────────────────────────────────────
test("12. validateSecurityAssessment passes on valid report", () => {
  const report = {
    schemaVersion: "payguard-evidence-v1",
    assessmentSchemaVersion: SECURITY_ASSESSMENT_SCHEMA_VERSION,
    overallStatus: "VERIFIED",
    dimensions: {
      securityVerdict: "PASS",
      verificationStatus: "VERIFIED",
      dataStatus: "FRESH",
      liquidityStatus: "HEALTHY"
    },
    normalizedFindings: []
  };
  const { valid, errors } = validateSecurityAssessment(report);
  assert.equal(valid, true, `Expected valid but got errors: ${JSON.stringify(errors)}`);
  assert.deepEqual(errors, []);
});

test("13. validateSecurityAssessment fails when dimensions is missing", () => {
  const report = {
    schemaVersion: "payguard-evidence-v1",
    assessmentSchemaVersion: SECURITY_ASSESSMENT_SCHEMA_VERSION,
    overallStatus: "VERIFIED",
    normalizedFindings: []
  };
  const { valid, errors } = validateSecurityAssessment(report);
  assert.equal(valid, false);
  assert.ok(errors.length > 0, "Expected validation errors");
});

test("14. validateSecurityAssessment fails when normalizedFindings is missing", () => {
  const report = {
    schemaVersion: "payguard-evidence-v1",
    assessmentSchemaVersion: SECURITY_ASSESSMENT_SCHEMA_VERSION,
    overallStatus: "VERIFIED",
    dimensions: {
      securityVerdict: "PASS",
      verificationStatus: "VERIFIED",
      dataStatus: "FRESH",
      liquidityStatus: "HEALTHY"
    }
  };
  const { valid, errors } = validateSecurityAssessment(report);
  assert.equal(valid, false);
  assert.ok(errors.length > 0);
});

test("15. validateSecurityAssessment fails when assessmentSchemaVersion is wrong", () => {
  const report = {
    schemaVersion: "payguard-evidence-v1",
    assessmentSchemaVersion: "wrong-version",
    overallStatus: "VERIFIED",
    dimensions: {
      securityVerdict: "PASS",
      verificationStatus: "VERIFIED",
      dataStatus: "FRESH",
      liquidityStatus: "HEALTHY"
    },
    normalizedFindings: []
  };
  const { valid } = validateSecurityAssessment(report);
  assert.equal(valid, false);
});

test("16. validateSecurityAssessment fails when securityVerdict is invalid enum", () => {
  const report = {
    schemaVersion: "payguard-evidence-v1",
    assessmentSchemaVersion: SECURITY_ASSESSMENT_SCHEMA_VERSION,
    overallStatus: "VERIFIED",
    dimensions: {
      securityVerdict: "MALICIOUS", // invalid
      verificationStatus: "VERIFIED",
      dataStatus: "FRESH",
      liquidityStatus: "HEALTHY"
    },
    normalizedFindings: []
  };
  const { valid } = validateSecurityAssessment(report);
  assert.equal(valid, false);
});


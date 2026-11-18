import test from "node:test";
import assert from "node:assert/strict";
import {
  createEvidence,
  validateEvidence,
  EVIDENCE_STATUSES
} from "../src/core/evidence.mjs";

const base = {
  sourceModule: "token-security",
  target: { type: "token", identifier: "0x0000000000000000000000000000000000000001" }
};

test("creates and validates a standardized evidence record", () => {
  const evidence = createEvidence(base);
  assert.equal(evidence.status, "PENDING");
  assert.equal(evidence.metadata.riskScore, 0);
  assert.equal(evidence.metadata.confidence, 0);
  assert.equal(validateEvidence(evidence), true);
});

test("enforces the fixed evidence status enum", () => {
  for (const status of EVIDENCE_STATUSES) {
    assert.equal(validateEvidence(createEvidence({ ...base, status })), true);
  }
  assert.throws(
    () => createEvidence({ ...base, status: "BLOCK" }),
    /status must be one of/
  );
});

test("validates riskScore and confidence boundaries without coercion", () => {
  assert.equal(validateEvidence(createEvidence({
    ...base,
    metadata: { riskScore: 100, confidence: 1 }
  })), true);

  for (const riskScore of [-1, 100.01, NaN, Infinity, "50", null]) {
    assert.throws(
      () => createEvidence({ ...base, metadata: { riskScore } }),
      /riskScore/
    );
  }
  for (const confidence of [-0.01, 1.01, NaN, Infinity, "0.5", null]) {
    assert.throws(
      () => createEvidence({ ...base, metadata: { confidence } }),
      /confidence/
    );
  }
});

test("normalizes GoPlus token/address finding objects", () => {
  const evidence = createEvidence({
    ...base,
    findings: [{
      code: "HONEYPOT_DETECTED",
      severity: "critical",
      message: "Token is identified as a honeypot."
    }]
  });
  assert.deepEqual(evidence.findings[0], {
    code: "HONEYPOT_DETECTED",
    severity: "critical",
    message: "Token is identified as a honeypot."
  });
  assert.equal(validateEvidence(evidence), true);
});

test("normalizes URL Sentinel and Calldata Inspector check objects", () => {
  const evidence = createEvidence({
    ...base,
    sourceModule: "url-sentinel",
    target: { type: "url", identifier: "https://example.com" },
    findings: [
      { id: "trusted_domain_match", severity: "info", status: "pass", detail: "Trusted domain matched." },
      { id: "unicode_bidi_override", severity: "high", status: "fail", detail: "Bidi control detected." },
      { id: "allowance_size", status: "WARN", detail: "Unlimited allowance." }
    ]
  });

  assert.deepEqual(evidence.findings, [
    { code: "trusted_domain_match", severity: "info", message: "Trusted domain matched.", status: "PASS" },
    { code: "unicode_bidi_override", severity: "high", message: "Bidi control detected.", status: "FAIL" },
    { code: "allowance_size", severity: "medium", message: "Unlimited allowance.", status: "WARN" }
  ]);
  assert.equal(validateEvidence(evidence), true);
});

test("rejects malformed target and finding structures", () => {
  assert.throws(
    () => createEvidence({ ...base, target: { type: "wallet", identifier: "0x123" } }),
    /target must contain/
  );
  assert.throws(
    () => createEvidence({ ...base, findings: [{ id: "missing-detail", status: "MAYBE" }] }),
    /severity|message|status/
  );
  assert.equal(validateEvidence({
    ...createEvidence(base),
    target: { type: "payload", identifier: "" }
  }), false);
});

import test from "node:test";
import assert from "node:assert/strict";
import { validatePlannerOutput, PlannerOutputValidationError } from "../src/agent/planner-validation.mjs";

const valid = () => ({
  schemaVersion: "1.0.2",
  planId: "plan-001",
  network: "base-mainnet",
  chainId: 8453,
  decision: "investigate",
  toolCalls: [{
    callId: "call-1",
    toolName: "payguard_analyze_url",
    purpose: "domain_reputation",
    priority: 1,
    targetRef: "https://example.com",
    toolInput: { url: "https://example.com" }
  }],
  stopReason: null
});

test("accepts valid Draft 2020-12 planner output", () => {
  const value = valid();
  assert.equal(validatePlannerOutput(value), value);
});

test("rejects a mismatched network and chain ID", () => {
  const value = valid();
  value.chainId = 84532;
  assert.throws(() => validatePlannerOutput(value), PlannerOutputValidationError);
});

test("rejects contradictory decision, stop reason and tool calls", () => {
  const value = valid();
  value.decision = "insufficient_input";
  value.stopReason = "insufficient_input";
  assert.throws(() => validatePlannerOutput(value), PlannerOutputValidationError);
});

test("rejects unknown tools even when the JSON shape is valid", () => {
  const value = valid();
  value.toolCalls[0].toolName = "execute_arbitrary_code";
  assert.throws(
    () => validatePlannerOutput(value),
    error => error instanceof PlannerOutputValidationError && error.code === "PLANNER_OUTPUT_TOOL_NOT_ALLOWED"
  );
});

test("rejects unknown properties", () => {
  const value = valid();
  value.untrustedOverride = true;
  assert.throws(() => validatePlannerOutput(value), PlannerOutputValidationError);
});

test("accepts a consistent insufficient-input response with no calls", () => {
  const value = valid();
  value.decision = "insufficient_input";
  value.toolCalls = [];
  value.stopReason = "insufficient_input";
  assert.equal(validatePlannerOutput(value), value);
});

test("rejects extra properties inside strict toolInput objects", () => {
  const value = valid();
  value.toolCalls[0].toolInput.extra = true;
  assert.throws(() => validatePlannerOutput(value), PlannerOutputValidationError);
});

test("rejects toolInput paired with a different registered tool", () => {
  const value = valid();
  value.toolCalls[0].toolName = "payguard_check_token_security";
  assert.throws(() => validatePlannerOutput(value), PlannerOutputValidationError);
});

test("rejects missing toolInput", () => {
  const value = valid();
  delete value.toolCalls[0].toolInput;
  assert.throws(() => validatePlannerOutput(value), PlannerOutputValidationError);
});

test("accepts the strict toolInput contract for each of the seven registered tools", () => {
  const address = "0x1111111111111111111111111111111111111111";
  const cases = [
    ["payguard_check_payment_intent", "https://merchant.example", {}],
    ["payguard_analyze_url", "https://example.com", { url: "https://example.com" }],
    ["payguard_prepare_threat_report", "https://example.com", { url: "https://example.com" }],
    ["payguard_inspect_calldata", address, {}],
    ["payguard_check_token_security", address, { contractAddress: address }],
    ["payguard_check_address_security", address, { address }],
    ["payguard_scan_wallet_tokens", address, { walletAddress: address }]
  ];
  for (const [toolName, targetRef, toolInput] of cases) {
    const value = valid();
    value.toolCalls[0] = {
      callId: "call-" + toolName,
      toolName,
      purpose: "evidence_enrichment",
      priority: 1,
      targetRef,
      toolInput
    };
    assert.equal(validatePlannerOutput(value), value, toolName);
  }
});

import test from "node:test";
import assert from "node:assert/strict";
import { dispatchValidatedPlannerOutput } from "../src/agent/planner-dispatcher.mjs";

const validPlan = () => ({
  schemaVersion: "1.0.2",
  planId: "plan-001",
  network: "base-mainnet",
  chainId: 8453,
  decision: "investigate",
  stopReason: null,
  toolCalls: [{
    callId: "call-1",
    toolName: "payguard_analyze_url",
    purpose: "domain_reputation",
    priority: 1,
    targetRef: "https://example.com",
    toolInput: { url: "https://example.com" }
  }]
});

test("validates then dispatches the planner call with trusted plan context", async () => {
  let dispatched;
  const result = await dispatchValidatedPlannerOutput({
    plannerOutput: validPlan(),
    dispatchToolCall: async (toolCall, context) => {
      dispatched = { toolCall, context };
      return { status: "accepted" };
    }
  });

  assert.equal(dispatched.toolCall.callId, "call-1");
  assert.equal(dispatched.toolCall.toolName, "payguard_analyze_url");
  assert.equal(dispatched.context.planId, "plan-001");
  assert.equal(dispatched.context.network, "base-mainnet");
  assert.equal(dispatched.context.chainId, 8453);
  assert.deepEqual(dispatched.context.dependencyResults, {});
  assert.equal(result.executions[0].status, "COMPLETED");
  assert.equal(result.evidence[0].status, "UNVERIFIED");
  assert.equal(result.assessment.overallStatus, "UNVERIFIED");
  assert.equal(result.finalDecision, "WARN");
});

test("Evidence Core, not the planner, determines the final security decision", async () => {
  const result = await dispatchValidatedPlannerOutput({
    plannerOutput: validPlan(),
    dispatchToolCall: async () => ({
      verdict: "CAUTION",
      riskLevel: "HIGH",
      findings: [{ code: "PHISHING_SIGNAL", severity: "HIGH" }]
    })
  });

  assert.equal(result.plannerDisposition, "investigate");
  assert.equal(result.evidence[0].status, "RISK_DETECTED");
  assert.equal(result.assessment.decision, "BLOCK");
  assert.equal(result.finalDecision, "BLOCK");
  assert.notEqual(result.finalDecision, result.plannerDisposition);
});

test("does not dispatch if schema validation fails", async () => {
  let dispatches = 0;
  const plannerOutput = validPlan();
  plannerOutput.chainId = 84532;

  await assert.rejects(dispatchValidatedPlannerOutput({
    plannerOutput,
    dispatchToolCall: async () => { dispatches++; }
  }), /schema validation/);

  assert.equal(dispatches, 0);
});

test("rejects tools outside the authorized PayGuard allowlist before any dispatch", async () => {
  let dispatches = 0;
  const plannerOutput = validPlan();
  plannerOutput.toolCalls[0].toolName = "execute_arbitrary_code";

  await assert.rejects(dispatchValidatedPlannerOutput({
    plannerOutput,
    dispatchToolCall: async () => { dispatches++; }
  }), error => error.code === "PLANNER_OUTPUT_TOOL_NOT_ALLOWED");

  assert.equal(dispatches, 0);
});

test("validates the complete dependency graph before dispatch", async () => {
  let dispatches = 0;
  const plannerOutput = validPlan();
  plannerOutput.toolCalls = [
    {
      ...plannerOutput.toolCalls[0],
      callId: "a",
      dependsOn: ["b"]
    },
    {
      ...plannerOutput.toolCalls[0],
      callId: "b",
      toolName: "payguard_check_token_security",
      purpose: "token_security",
      targetRef: "0x1111111111111111111111111111111111111111",
      toolInput: { contractAddress: "0x1111111111111111111111111111111111111111" },
      dependsOn: ["a"]
    }
  ];

  await assert.rejects(dispatchValidatedPlannerOutput({
    plannerOutput,
    dispatchToolCall: async () => { dispatches++; }
  }), /cycle/);

  assert.equal(dispatches, 0);
});

test("dispatches dependency chain in order and passes prior results", async () => {
  const order = [];
  let receivedDependency;
  const plannerOutput = validPlan();
  plannerOutput.toolCalls = [
    {
      ...plannerOutput.toolCalls[0],
      callId: "second",
      toolName: "payguard_check_address_security",
      purpose: "address_reputation",
      targetRef: "0x2222222222222222222222222222222222222222",
      toolInput: { address: "0x2222222222222222222222222222222222222222" },
      dependsOn: ["first"]
    },
    {
      ...plannerOutput.toolCalls[0],
      callId: "first"
    }
  ];

  const result = await dispatchValidatedPlannerOutput({
    plannerOutput,
    dispatchToolCall: async (toolCall, context) => {
      order.push(toolCall.callId);
      if (toolCall.callId === "first") return { resolvedTarget: "0xabc" };
      receivedDependency = context.dependencyResults.first.resolvedTarget;
      return { checked: true };
    }
  });

  assert.deepEqual(order, ["first", "second"]);
  assert.equal(receivedDependency, "0xabc");
  assert.deepEqual(result.executions.map(item => item.status), ["COMPLETED", "COMPLETED"]);
  assert.equal(result.evidence.length, 2);
  assert.equal(result.assessment.evidenceCoverage.length, 2);
});

test("returns a validated no-dispatch outcome for non-investigate planner disposition", async () => {
  let dispatches = 0;
  const plannerOutput = validPlan();
  plannerOutput.decision = "insufficient_input";
  plannerOutput.stopReason = "insufficient_input";
  plannerOutput.toolCalls = [];

  const result = await dispatchValidatedPlannerOutput({
    plannerOutput,
    dispatchToolCall: async () => { dispatches++; }
  });

  assert.equal(result.plannerDisposition, "insufficient_input");
  assert.equal(result.assessment.overallStatus, "NOT_CHECKED");
  assert.equal(result.finalDecision, "WARN");
  assert.deepEqual(result.executions, []);
  assert.equal(dispatches, 0);
});

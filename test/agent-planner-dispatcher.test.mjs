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
});

test("structured ERROR evidence blocks dependent calls as NOT_CHECKED", async () => {
  let dependentDispatches = 0;
  const plannerOutput = validPlan();
  plannerOutput.toolCalls = [
    { ...plannerOutput.toolCalls[0], callId: "prerequisite" },
    {
      ...plannerOutput.toolCalls[0],
      callId: "dependent",
      toolName: "payguard_prepare_threat_report",
      purpose: "threat_report",
      targetRef: "https://example.com",
      toolInput: { url: "https://example.com" },
      dependsOn: ["prerequisite"]
    }
  ];
  const result = await dispatchValidatedPlannerOutput({
    plannerOutput,
    dispatchToolCall: async call => {
      if (call.callId === "dependent") dependentDispatches++;
      return { status: "ERROR", error: "provider unavailable" };
    }
  });
  assert.equal(result.executions[0].evidence.status, "ERROR");
  assert.equal(result.executions[1].evidence.status, "NOT_CHECKED");
  assert.equal(dependentDispatches, 0);
});

test("planner per-tool timeout is ERROR and total budget leaves unstarted calls NOT_CHECKED", async () => {
  const plannerOutput = validPlan();
  plannerOutput.toolCalls = [
    { ...plannerOutput.toolCalls[0], callId: "slow-first" },
    {
      ...plannerOutput.toolCalls[0],
      callId: "never-started",
      toolName: "payguard_prepare_threat_report",
      purpose: "threat_report",
      targetRef: "https://example.com",
      toolInput: { url: "https://example.com" }
    }
  ];
  const result = await dispatchValidatedPlannerOutput({
    plannerOutput,
    maxConcurrency: 1,
    perToolTimeoutMs: 100,
    totalTimeoutMs: 15,
    dispatchToolCall: () => new Promise(() => {})
  });
  assert.equal(result.executions[0].evidence.status, "ERROR");
  assert.equal(result.executions[0].errorCode, "TOOL_TIMEOUT");
  assert.equal(result.executions[1].evidence.status, "NOT_CHECKED");
});

test("returns a validated no-dispatch outcome for non-investigate decisions", async () => {
  let dispatches = 0;
  const plannerOutput = validPlan();
  plannerOutput.decision = "insufficient_input";
  plannerOutput.stopReason = "insufficient_input";
  plannerOutput.toolCalls = [];

  const result = await dispatchValidatedPlannerOutput({
    plannerOutput,
    dispatchToolCall: async () => { dispatches++; }
  });

  assert.equal(result.decision, "insufficient_input");
  assert.deepEqual(result.executions, []);
  assert.equal(dispatches, 0);
});


test("validated dispatcher returns Evidence Core assessment and normalized tool evidence", async () => {
  const plan = {
    schemaVersion: "1.0.2", planId: "p-evidence", network: "base-mainnet", chainId: 8453,
    decision: "investigate", stopReason: null,
    toolCalls: [{
      callId: "url-1",
      toolName: "payguard_analyze_url",
      purpose: "domain_reputation",
      priority: 1,
      targetRef: "https://evil.example",
      toolInput: { url: "https://evil.example" }
    }]
  };
  const result = await dispatchValidatedPlannerOutput({
    plannerOutput: plan,
    dispatchToolCall: async () => ({
      verdict: "KNOWN_MALICIOUS",
      riskLevel: "CRITICAL",
      checks: [{ id: "threat_match", severity: "CRITICAL", status: "fail", detail: "Known phishing domain." }]
    })
  });
  assert.equal(result.executions[0].evidence.status, "RISK_DETECTED");
  assert.equal(result.assessment.decision, "BLOCK");
  assert.ok(result.assessment.findings.some(f => f.severity === "CRITICAL"));
});

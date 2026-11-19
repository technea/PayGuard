import test from "node:test";
import assert from "node:assert/strict";
import { createPayGuardToolExecutor } from "../src/agent/payguard-executor.mjs";
import { runPayGuardInvestigation } from "../src/agent/investigation.mjs";
import { createPayGuardAgentMcpPlugin, PAYGUARD_INVESTIGATION_TOOL } from "../src/agent/mcp.mjs";

const ASSET = "0x1111111111111111111111111111111111111111";
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const OTHER = "0x3333333333333333333333333333333333333333";

function paymentContext(recipient = RECIPIENT) {
  return {
    intent: { trusted: true },
    paymentRequirements: {
      accepts: [{
        network: "eip155:8453",
        asset: ASSET,
        payTo: RECIPIENT,
        amount: "5000000"
      }]
    },
    transaction: { network: "8453", to: ASSET, data: "0x" },
    selectedPaymentIndex: 0,
    expectedRecipient: recipient
  };
}

function integrationPlugin({ recipient = RECIPIENT, rejectToken = false } = {}) {
  const calls = [];
  return {
    calls,
    tools: [],
    invokeTool(name, input) {
      calls.push({ name, input });
      if (name === "payguard_check_payment_intent") {
        return {
          status: "PASS",
          candidateResults: [{ index: 0, status: "PASS", checks: [] }]
        };
      }
      if (name === "payguard_inspect_calldata") {
        return {
          verdict: "PASS",
          operation: "ERC20_TRANSFER",
          details: { tokenContract: ASSET, recipient, amount: "5000000" },
          checks: [{ id: "calldata_decode", status: "PASS" }]
        };
      }
      if (name === "payguard_check_token_security" && rejectToken) {
        return Promise.reject(new Error("provider unavailable"));
      }
      if (name === "payguard_check_token_security") {
        return { verdict: "PASS", dataStatus: "AVAILABLE", findings: [] };
      }
      throw new Error("Unexpected tool: " + name);
    }
  };
}

const checks = [
  { toolName: "payguard_check_payment_intent", input: { intent: { trusted: true }, paymentRequirements: { accepts: [{ network: "eip155:8453", asset: ASSET, payTo: RECIPIENT, amount: "5000000" }] } } },
  { toolName: "payguard_inspect_calldata", input: { to: ASSET, data: "0x" } }
];

test("runtime adapter delegates only the named tool and preserves input", async () => {
  const calls = [];
  const fakePlugin = {
    invokeTool(name, input) {
      calls.push({ name, input });
      return { verdict: "PASS", dataStatus: "AVAILABLE" };
    }
  };
  const execute = createPayGuardToolExecutor(fakePlugin);
  const input = { contractAddress: "0x0000000000000000000000000000000000000001" };
  const result = await execute("payguard_check_token_security", input);
  assert.deepEqual(calls, [{ name: "payguard_check_token_security", input }]);
  assert.equal(result.verdict, "PASS");
});

test("integrated investigation returns normalized evidence from existing handlers", async () => {
  const calls = [];
  const fakePlugin = {
    invokeTool(name, input) {
      calls.push(name);
      assert.deepEqual(input, { url: "https://example.org" });
      return { verdict: "EXPECTED_DOMAIN_MATCH", checks: [] };
    }
  };
  const report = await runPayGuardInvestigation({
    subject: { type: "url", value: "https://example.org" },
    checks: [{ toolName: "payguard_analyze_url", input: { url: "https://example.org" } }],
    targetPlugin: fakePlugin
  });
  assert.deepEqual(calls, ["payguard_analyze_url"]);
  assert.equal(report.overallStatus, "VERIFIED");
  assert.equal(report.evidence[0].source, "payguard_analyze_url");
  assert.equal(report.evidence[0].status, "VERIFIED");
  assert.equal(report.execution.mode, "EXPLICIT_PLAN");
  assert.equal(report.assessment.decision, "ALLOW");
});

test("runner evidence, payment correlation, and Evidence Core form one verified pipeline", async () => {
  const fakePlugin = integrationPlugin();
  const report = await runPayGuardInvestigation({
    subject: { type: "transaction", value: "payment-intent" },
    checks,
    assessmentInput: paymentContext(),
    targetPlugin: fakePlugin
  });
  assert.equal(fakePlugin.calls.length, 2);
  assert.equal(report.correlation.status, "VERIFIED");
  assert.equal(report.overallStatus, "VERIFIED");
  assert.equal(report.assessment.overallStatus, "VERIFIED");
  assert.equal(report.assessment.decision, "ALLOW");
  assert.equal(report.assessment.confidence, 1);
  assert.equal(report.evidence.length, 3);
  assert.equal(typeof report.evidence[2].rawOutputSha256, "string");
});

test("correlation mismatch overrides passing scanner results and prevents ALLOW", async () => {
  const fakePlugin = integrationPlugin({ recipient: OTHER });
  const report = await runPayGuardInvestigation({
    checks,
    assessmentInput: paymentContext(),
    targetPlugin: fakePlugin
  });
  assert.equal(report.correlation.status, "RISK_DETECTED");
  assert.equal(report.assessment.overallStatus, "RISK_DETECTED");
  assert.equal(report.assessment.decision, "BLOCK");
  assert.ok(report.assessment.findings.some(item => item.category === "CALLDATA"));
});

test("runner ERROR remains visible and cannot produce an ALLOW assessment", async () => {
  const fakePlugin = integrationPlugin({ rejectToken: true });
  const report = await runPayGuardInvestigation({
    checks: [
      ...checks,
      { toolName: "payguard_check_token_security", input: { contractAddress: ASSET } }
    ],
    assessmentInput: paymentContext(),
    targetPlugin: fakePlugin
  });
  assert.equal(report.evidence.find(item => item.source === "payguard_check_token_security").status, "ERROR");
  assert.equal(report.assessment.overallStatus, "ERROR");
  assert.equal(report.assessment.decision, "WARN");
});

test("correlation is explicitly NOT_CHECKED when payment context is incomplete", async () => {
  const report = await runPayGuardInvestigation({
    checks,
    assessmentInput: { transaction: { network: "8453" }, intent: { trusted: true } },
    targetPlugin: integrationPlugin()
  });
  assert.equal(report.correlation.status, "NOT_CHECKED");
  assert.equal(report.assessment.overallStatus, "NOT_CHECKED");
  assert.equal(report.assessment.decision, "WARN");
});

test("correlation reserves an Evidence Core record slot", async () => {
  const tooMany = Array.from({ length: 32 }, (_, index) => ({
    toolName: [
      "payguard_check_payment_intent",
      "payguard_inspect_calldata",
      "payguard_analyze_url",
      "payguard_prepare_threat_report",
      "payguard_check_token_security",
      "payguard_check_address_security",
      "payguard_scan_wallet_tokens"
    ][index % 7],
    input: {}
  }));
  await assert.rejects(runPayGuardInvestigation({
    checks: tooMany,
    assessmentInput: paymentContext(),
    targetPlugin: integrationPlugin()
  }), /at most 31 tool checks/);
});

test("adapter rejects a target without invokeTool", () => {
  assert.throws(() => createPayGuardToolExecutor({}), /invokeTool/);
});

test("integrated investigation still rejects unknown tools before invoking plugin", async () => {
  let calls = 0;
  const fakePlugin = { invokeTool() { calls++; return {}; } };
  await assert.rejects(runPayGuardInvestigation({
    checks: [{ toolName: "payguard_unknown", input: {} }],
    targetPlugin: fakePlugin
  }), /Unknown PayGuard tool/);
  assert.equal(calls, 0);
});

test("MCP integration exposes a separate aggregate investigation tool", async () => {
  const fakePlugin = integrationPlugin();
  const agentPlugin = createPayGuardAgentMcpPlugin({ targetPlugin: fakePlugin });
  assert.equal(agentPlugin.tools.length, 1);
  assert.equal(agentPlugin.tools[0].name, "payguard_run_investigation");
  assert.equal(PAYGUARD_INVESTIGATION_TOOL.inputSchema.properties.checks.maxItems, 32);
  const report = await agentPlugin.invokeTool("payguard_run_investigation", {
    checks: [{ toolName: "payguard_check_payment_intent", input: {} }],
    targetPlugin: undefined
  });
  assert.equal(report.execution.mode, "EXPLICIT_PLAN");
  assert.equal(report.assessment.decision, "ALLOW");
});

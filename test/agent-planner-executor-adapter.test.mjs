import test from "node:test";
import assert from "node:assert/strict";
import { mapPlannerToolInput, createPlannerExecutorAdapter, compilePayGuardToolInputSchemas } from "../src/agent/planner-executor-adapter.mjs";
import { dispatchValidatedPlannerOutput } from "../src/agent/planner-dispatcher.mjs";

const MAINNET = { planId: "p-1", network: "base-mainnet", chainId: 8453 };
const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";
const call = (toolName, targetRef, toolInput) => ({ callId: "c-1", toolName, purpose: "evidence_enrichment", priority: 1, targetRef, toolInput });

test("maps URL analysis input and merges only trusted URL options", () => {
  assert.deepEqual(mapPlannerToolInput(
    call("payguard_analyze_url", "https://example.com", { url: "https://example.com" }),
    MAINNET,
    { urlAnalysisOptions: { expectedDomain: "example.com", checkReputation: true, ignored: "no" } }
  ), { url: "https://example.com", expectedDomain: "example.com", checkReputation: true });
});

test("maps threat report URL and trusted context", () => {
  assert.deepEqual(mapPlannerToolInput(
    call("payguard_prepare_threat_report", "https://example.com/report", { url: "https://example.com/report" }),
    MAINNET,
    { threatReportOptions: { trustedDomains: ["example.com"] } }
  ), { url: "https://example.com/report", trustedDomains: ["example.com"] });
});

test("maps token and address checks with the plan chain binding", () => {
  assert.deepEqual(mapPlannerToolInput(call("payguard_check_token_security", A, { contractAddress: A }), MAINNET), { contractAddress: A, chainId: 8453 });
  assert.deepEqual(mapPlannerToolInput(call("payguard_check_address_security", B, { address: B }), MAINNET), { address: B, chainId: 8453 });
});

test("maps wallet scan and rejects Base Sepolia for Base Mainnet-only scanners", () => {
  assert.deepEqual(mapPlannerToolInput(
    call("payguard_scan_wallet_tokens", A, { walletAddress: A, customTokenAddresses: [B] }),
    MAINNET
  ), { walletAddress: A, customTokenAddresses: [B] });
  assert.throws(() => mapPlannerToolInput(
    call("payguard_scan_wallet_tokens", A, { walletAddress: A }),
    { ...MAINNET, network: "base-sepolia", chainId: 84532 }
  ), /Base Mainnet only/);
});

test("maps calldata only from trusted transaction context", () => {
  assert.deepEqual(mapPlannerToolInput(
    call("payguard_inspect_calldata", A, {}),
    MAINNET,
    { transaction: { to: A, value: "0", data: "0x1234" }, transactionPolicy: { maxNativeValue: "0" } }
  ), { to: A, value: "0", data: "0x1234", network: "8453", policy: { maxNativeValue: "0" } });
  assert.throws(() => mapPlannerToolInput(call("payguard_inspect_calldata", A, {}), MAINNET), /trustedContext.transaction/);
});

test("maps payment intent only from trusted application context", () => {
  const payment = {
    intent: { expectedResourceUrl: "https://merchant.example", maxAmountAtomic: "100", allowedNetworks: ["eip155:8453"], allowedAssets: [A], allowedPayTo: [B], maxTimeoutSeconds: 60 },
    paymentRequirements: { resource: "https://merchant.example", accepts: [{ scheme: "exact" }] }
  };
  assert.deepEqual(mapPlannerToolInput(
    call("payguard_check_payment_intent", "https://merchant.example", {}),
    MAINNET,
    { payment }
  ), payment);
  assert.throws(() => mapPlannerToolInput(call("payguard_check_payment_intent", "https://merchant.example", {}), MAINNET), /trustedContext.payment/);
});

test("rejects mismatched target references and unauthorized tool names", () => {
  assert.throws(() => mapPlannerToolInput(call("payguard_analyze_url", "https://evil.example", { url: "https://good.example" }), MAINNET), /targetRef/);
  assert.throws(() => mapPlannerToolInput(call("exec_shell", "x", {}), MAINNET), error => error.code === "PLANNER_OUTPUT_TOOL_NOT_ALLOWED");
});

test("integrates adapter with validated dispatcher and existing invokeTool boundary", async () => {
  const invoked = [];
  const targetPlugin = {
    invokeTool: async (name, input) => { invoked.push({ name, input }); return { status: "UNVERIFIED" }; }
  };
  const plan = {
    schemaVersion: "1.0.2", planId: "p-1", network: "base-mainnet", chainId: 8453,
    decision: "investigate", stopReason: null,
    toolCalls: [call("payguard_analyze_url", "https://example.com", { url: "https://example.com" })]
  };
  const result = await dispatchValidatedPlannerOutput({ plannerOutput: plan, targetPlugin });
  assert.equal(invoked.length, 1);
  assert.deepEqual(invoked[0], { name: "payguard_analyze_url", input: { url: "https://example.com" } });
  assert.equal(result.executions[0].status, "COMPLETED");
});

test("adapter is exposed as a trusted callback for dependency scheduler integration", async () => {
  const invoked = [];
  const adapter = createPlannerExecutorAdapter({
    targetPlugin: { invokeTool: async (name, input) => { invoked.push({ name, input }); return true; } }
  });
  const result = await adapter(
    call("payguard_analyze_url", "https://example.com", { url: "https://example.com" }),
    MAINNET
  );
  assert.equal(result, true);
  assert.equal(invoked[0].name, "payguard_analyze_url");
});


test("compiles the registered input schemas for all seven planner tools", () => {
  const validators = compilePayGuardToolInputSchemas();
  assert.equal(validators.size, 7);
  for (const name of [
    "payguard_check_payment_intent",
    "payguard_analyze_url",
    "payguard_prepare_threat_report",
    "payguard_inspect_calldata",
    "payguard_check_token_security",
    "payguard_check_address_security",
    "payguard_scan_wallet_tokens"
  ]) {
    assert.equal(typeof validators.get(name), "function", name + " schema should be compiled");
  }
});

test("rejects malformed mapped payloads before crossing invokeTool boundary", async () => {
  const invoked = [];
  const adapter = createPlannerExecutorAdapter({
    targetPlugin: {
      invokeTool: async (name, input) => {
        invoked.push({ name, input });
        return true;
      }
    }
  });

  await assert.rejects(
    adapter(
      call("payguard_scan_wallet_tokens", A, {
        walletAddress: A,
        customTokenAddresses: "not-an-array"
      }),
      MAINNET
    ),
    error => error.code === "PLANNER_TOOL_INPUT_SCHEMA_INVALID" &&
      error.toolName === "payguard_scan_wallet_tokens" &&
      Array.isArray(error.validationErrors) &&
      error.validationErrors.length > 0
  );
  assert.equal(invoked.length, 0, "invalid mapped inputs must never invoke the plugin");
});

test("valid mapped inputs pass registered plugin schema before invokeTool", async () => {
  const invoked = [];
  const adapter = createPlannerExecutorAdapter({
    targetPlugin: {
      invokeTool: async (name, input) => {
        invoked.push({ name, input });
        return true;
      }
    }
  });

  const result = await adapter(
    call("payguard_check_token_security", A, { contractAddress: A }),
    MAINNET
  );
  assert.equal(result, true);
  assert.deepEqual(invoked, [{
    name: "payguard_check_token_security",
    input: { contractAddress: A, chainId: 8453 }
  }]);
});


test("preflights every mapped input before dispatching any tool in the plan", async () => {
  const invoked = [];
  const targetPlugin = {
    invokeTool: async (name, input) => {
      invoked.push({ name, input });
      return { status: "UNVERIFIED" };
    }
  };
  const plan = {
    schemaVersion: "1.0.2", planId: "p-preflight", network: "base-mainnet", chainId: 8453,
    decision: "investigate", stopReason: null,
    toolCalls: [
      call("payguard_analyze_url", "https://example.com", { url: "https://example.com" }),
      {
        ...call("payguard_check_payment_intent", "https://merchant.example", {}),
        callId: "c-2",
        priority: 2
      }
    ]
  };

  await assert.rejects(
    dispatchValidatedPlannerOutput({ plannerOutput: plan, targetPlugin }),
    /trustedContext.payment/
  );
  assert.equal(invoked.length, 0, "no tool may run if any mapped call fails preflight");
});

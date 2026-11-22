import test, { beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import plugin from "../src/plugin.mjs";
import { normalizeToolResult } from "../src/agent/normalize-result.mjs";
import { buildEvidenceCore } from "../src/core/evidence.mjs";
import { runDependentToolCalls } from "../src/agent/runner.mjs";
import { dispatchValidatedPlannerOutput } from "../src/agent/planner-dispatcher.mjs";
import { clearTokenCache } from "../src/token-security.mjs";

beforeEach(() => clearTokenCache());
afterEach(() => clearTokenCache());

const WALLET = "0x1111111111111111111111111111111111111111";
const TOKEN = "0x2222222222222222222222222222222222222222";
const RECIPIENT = "0x3333333333333333333333333333333333333333";
const URL_TOOL = "payguard_analyze_url";
const WALLET_TOOL = "payguard_scan_wallet_tokens";

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
    text: async () => JSON.stringify(payload)
  };
}

function registeredHandler(name) {
  const tool = plugin.tools.find(candidate => candidate.name === name);
  assert.ok(tool, "registered tool exists: " + name);
  assert.equal(typeof tool.handler, "function", "registered handler exists: " + name);
  return tool.handler;
}

function maliciousGoPlusToken(contractAddress) {
  return response({
    code: 1,
    message: "OK",
    result: {
      [contractAddress.toLowerCase()]: {
        token_name: "Mock Honeypot",
        token_symbol: "HONEYPOT",
        is_honeypot: "1",
        cannot_sell_all: "1",
        buy_tax: "0",
        sell_tax: "0.99"
      }
    }
  });
}

function maliciousGoPlusAddress() {
  return response({
    code: 1,
    message: "OK",
    result: {
      phishing_activities: "1",
      stealing_attack: "0",
      sanctioned: "0"
    }
  });
}

function createProviderMock({ walletIndexer = "alchemy", tokenRisk = true } = {}) {
  const calls = [];
  const fetchImpl = async (input, init = {}) => {
    const url = String(input);
    calls.push({ url, method: init.method || "GET", body: init.body || null });

    if (url.includes("/api/v1/token_security/")) {
      const parsed = new URL(url);
      const address = parsed.searchParams.get("contract_addresses") || TOKEN;
      return tokenRisk
        ? maliciousGoPlusToken(address)
        : response({ code: 1, message: "OK", result: {} });
    }

    if (url.includes("/api/v1/address_security/")) {
      return maliciousGoPlusAddress();
    }

    if (url.includes("alchemy_getTokenBalances") || url.includes("base-mainnet.g.alchemy.com")) {
      const body = init.body ? JSON.parse(init.body) : {};
      if (body.method === "alchemy_getTokenBalances") {
        return response({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            tokenBalances: [{ contractAddress: TOKEN, tokenBalance: "0x1" }]
          }
        });
      }
      if (body.method === "alchemy_getTokenMetadata") {
        return response({
          jsonrpc: "2.0",
          id: body.id,
          result: { name: "Mock Token", symbol: "MOCK", decimals: 18 }
        });
      }
      if (body.method === "eth_getBalance" || body.method === "eth_call") {
        return response({ jsonrpc: "2.0", id: body.id, result: "0x0" });
      }
    }

    if (url.includes("/addresses/") && url.includes("/tokens?type=ERC-20")) {
      if (walletIndexer === "blockscout") {
        return response({
          items: [{
            token: {
              address: TOKEN,
              name: "Mock Token",
              symbol: "MOCK",
              decimals: "18"
            },
            value: "1"
          }]
        });
      }
      return response({ items: [] });
    }

    // Metadata/balance RPC fallbacks for canonical registry tokens.
    const body = init.body ? JSON.parse(init.body) : {};
    if (body.method === "eth_getBalance" || body.method === "eth_call") {
      return response({ jsonrpc: "2.0", id: body.id, result: "0x0" });
    }

    return response({ error: "Unexpected deterministic mock request: " + url }, 404);
  };

  return { fetchImpl, calls };
}

function paymentIntentInput() {
  return {
    intent: {
      expectedResourceUrl: "https://merchant.example/pay",
      maxAmountAtomic: "100",
      allowedNetworks: ["eip155:8453"],
      allowedAssets: [TOKEN],
      allowedPayTo: [RECIPIENT],
      allowedSchemes: ["exact"],
      maxTimeoutSeconds: 300
    },
    paymentRequirements: {
      resource: "https://merchant.example/pay",
      accepts: [null]
    }
  };
}

test("actual seven registered handlers preserve high-risk provider signals into Evidence Core", async () => {
  const provider = createProviderMock();
  const cases = [
    [ "payguard_check_payment_intent", paymentIntentInput(), {} ],
    [ URL_TOOL, { url: "javascript:alert(1)" }, {} ],
    [ "payguard_prepare_threat_report", { url: "javascript:alert(1)" }, {} ],
    [ "payguard_inspect_calldata", {
      to: TOKEN,
      value: "0",
      data: "0x",
      policy: { allowedTargets: [RECIPIENT] }
    }, {} ],
    [ "payguard_check_token_security", { contractAddress: TOKEN, chainId: "8453" }, {
      fetchImpl: provider.fetchImpl
    } ],
    [ "payguard_check_address_security", { address: WALLET, chainId: "8453" }, {
      fetchImpl: provider.fetchImpl
    } ],
    [ WALLET_TOOL, { walletAddress: WALLET }, {
      fetchImpl: provider.fetchImpl,
      alchemyApiKey: "deterministic-test-key"
    } ]
  ];

  for (const [toolName, input, options] of cases) {
    const raw = await registeredHandler(toolName)(input, options);
    const evidence = normalizeToolResult(toolName, raw, {
      id: "handler-integration:" + toolName,
      completedAt: "2026-01-01T00:00:00.000Z"
    });
    assert.equal(evidence.status, "RISK_DETECTED", toolName);
    assert.ok(evidence.evidence.length > 0, toolName);
    const assessment = buildEvidenceCore([evidence]);
    assert.ok(
      assessment.decision === "BLOCK" || assessment.decision === "WARN",
      toolName + " must not become ALLOW when its handler reports a risk"
    );
    assert.ok(assessment.findings.length > 0, toolName);
  }

  assert.ok(provider.calls.some(call => call.url.includes("api.gopluslabs.io")));
});

test("planner-to-Evidence-Core pipeline validates, adapts, invokes the registered handler, and preserves CRITICAL risk", async () => {
  const provider = createProviderMock();
  const registeredPlugin = {
    tools: plugin.tools,
    invokeTool(name, input) {
      const tool = plugin.tools.find(candidate => candidate.name === name);
      assert.ok(tool, "adapter dispatches only a registered plugin tool");
      return tool.handler(input, { fetchImpl: provider.fetchImpl });
    }
  };
  const plannerOutput = {
    schemaVersion: "1.0.2",
    planId: "full-pipeline-token-risk",
    network: "base-mainnet",
    chainId: 8453,
    decision: "investigate",
    stopReason: null,
    toolCalls: [{
      callId: "token-security-1",
      toolName: "payguard_check_token_security",
      purpose: "token_security",
      priority: 1,
      targetRef: TOKEN,
      toolInput: { contractAddress: TOKEN }
    }]
  };

  const result = await dispatchValidatedPlannerOutput({
    plannerOutput,
    targetPlugin: registeredPlugin,
    perToolTimeoutMs: 3000,
    totalTimeoutMs: 5000
  });

  assert.equal(result.executions.length, 1);
  assert.equal(result.executions[0].status, "COMPLETED");
  assert.equal(result.executions[0].evidence.status, "RISK_DETECTED");
  assert.equal(result.assessment.decision, "BLOCK");
  assert.ok(result.assessment.findings.some(finding => finding.severity === "CRITICAL"));
  assert.ok(provider.calls.some(call => call.url.includes("/api/v1/token_security/")));
});

test("actual wallet handler consumes a complete Alchemy indexer response and retains token risk", async () => {
  const provider = createProviderMock({ walletIndexer: "alchemy" });
  const raw = await registeredHandler(WALLET_TOOL)(
    { walletAddress: WALLET },
    { fetchImpl: provider.fetchImpl, alchemyApiKey: "deterministic-test-key" }
  );

  assert.equal(raw.scanCompletionStatus, "COMPLETE");
  assert.equal(raw.discoveryMode, "ALCHEMY_INDEXER");
  assert.ok(provider.calls.some(call => call.body && JSON.parse(call.body).method === "alchemy_getTokenBalances"));
  assert.ok(provider.calls.some(call => call.url.includes("/api/v1/token_security/")));
  const evidence = normalizeToolResult(WALLET_TOOL, raw);
  assert.equal(evidence.status, "RISK_DETECTED");
  assert.equal(buildEvidenceCore([evidence]).decision, "BLOCK");
});

test("actual wallet handler consumes a complete Blockscout indexer response and retains token risk", async () => {
  const provider = createProviderMock({ walletIndexer: "blockscout" });
  const raw = await registeredHandler(WALLET_TOOL)(
    { walletAddress: WALLET },
    { fetchImpl: provider.fetchImpl, alchemyApiKey: false }
  );

  assert.equal(raw.scanCompletionStatus, "COMPLETE");
  assert.equal(raw.discoveryMode, "BLOCKSCOUT_INDEXER");
  assert.ok(provider.calls.some(call => call.url.includes("/addresses/") && call.url.includes("/tokens?type=ERC-20")));
  assert.ok(provider.calls.some(call => call.url.includes("/api/v1/token_security/")));
  const evidence = normalizeToolResult(WALLET_TOOL, raw);
  assert.equal(evidence.status, "RISK_DETECTED");
  assert.equal(buildEvidenceCore([evidence]).decision, "BLOCK");
});

test("unkeyed CRITICAL findings retain severity and message with a deterministic identifier", () => {
  const raw = {
    status: "UNVERIFIED",
    findings: [{ severity: "CRITICAL", message: "Critical exploit indicator without a source identifier." }]
  };
  const first = normalizeToolResult(URL_TOOL, raw);
  const second = normalizeToolResult(URL_TOOL, raw);
  assert.equal(first.evidence.length, 1);
  assert.equal(first.evidence[0].severity, "CRITICAL");
  assert.equal(first.evidence[0].message, raw.findings[0].message);
  assert.equal(first.evidence[0].code, second.evidence[0].code);
  assert.match(first.evidence[0].code, /^CRITICAL_FINDING_[A-F0-9]{16}$/);
});

test("UNVERIFIED handler output and ERROR/NOT_CHECKED runner states cannot become ALLOW", async () => {
  clearTokenCache();
  const provider = createProviderMock({ tokenRisk: false });
  const raw = await registeredHandler("payguard_check_token_security")(
    { contractAddress: TOKEN, chainId: "8453" },
    { fetchImpl: provider.fetchImpl }
  );
  const unverified = normalizeToolResult("payguard_check_token_security", raw);
  assert.equal(unverified.status, "UNVERIFIED");
  assert.equal(buildEvidenceCore([unverified]).decision, "WARN");

  const executions = await runDependentToolCalls({
    toolCalls: [
      { callId: "failed", toolName: URL_TOOL, dependsOn: [] },
      { callId: "skipped", toolName: "payguard_prepare_threat_report", dependsOn: ["failed"] }
    ],
    dispatchToolCall: async () => {
      throw new Error("deterministic mocked handler/provider failure");
    }
  });

  assert.equal(executions[0].evidence.status, "ERROR");
  assert.equal(executions[1].evidence.status, "NOT_CHECKED");
  const assessment = buildEvidenceCore(executions.map(item => item.evidence));
  assert.equal(assessment.decision, "WARN");
  assert.notEqual(assessment.decision, "ALLOW");
});

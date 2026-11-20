import test from "node:test";
import assert from "node:assert/strict";
import plugin from "../src/plugin.mjs";
import { normalizeToolResult } from "../src/agent/normalize-result.mjs";
import { buildEvidenceCore } from "../src/core/evidence.mjs";
import { runDependentToolCalls } from "../src/agent/runner.mjs";

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

test("actual wallet handler consumes a complete Alchemy indexer response and retains token risk", async () => {
  const provider = createProviderMock({ walletIndexer: "alchemy" });
  const raw = await registeredHandler(WALLET_TOOL)(
    { walletAddress: WALLET },
    { fetchImpl: provider.fetchImpl, alchemyApiKey: "deterministic-test-key" }
  );

  assert.equal(raw.scanCompletionStatus, "COMPLETE");
  assert.equal(raw.discoveryMode, "ALCHEMY_INDEXER");
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
  const evidence = normalizeToolResult(WALLET_TOOL, raw);
  assert.equal(evidence.status, "RISK_DETECTED");
  assert.equal(buildEvidenceCore([evidence]).decision, "BLOCK");
});

test("UNVERIFIED handler output and ERROR/NOT_CHECKED runner states cannot become ALLOW", async () => {
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

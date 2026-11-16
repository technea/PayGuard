import test from "node:test";
import assert from "node:assert/strict";
import {
  X402_CONFIG,
  BAZAAR_DISCOVERY_METADATA,
  build402Challenge,
  verifyPaymentProof,
  payboxIntegration
} from "../paybox.mjs";
import { createInMemoryX402ReplayGuard } from "../src/x402-replay-guard.mjs";

let liveNonceCounter = 10;
function makeLivePaymentPayload() {
  liveNonceCounter += 1;
  return {
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "1000", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo, extra: { assetTransferMethod: "eip3009" } },
    payload: {
      signature: "0x" + "11".repeat(65),
      authorization: {
        from: "0x857b06519e91e3a54538791bdbb0e22373e36b66",
        to: X402_CONFIG.payTo,
        value: "1000", validAfter: "0", validBefore: "1999999999",
        nonce: "0x" + liveNonceCounter.toString(16).padStart(64, "0")
      }
    }
  };
}


test("x402 route configuration and challenge matches official specification", () => {
  const challenge = build402Challenge("https://api.payguard.example/api/analyze-url");
  assert.equal(challenge.status, 402);
  assert.ok(challenge.headers["www-authenticate"].includes('scheme="exact"'));
  assert.ok(challenge.headers["www-authenticate"].includes(`network="${X402_CONFIG.network}"`));
  assert.equal(challenge.body.error, "Payment Required");
  assert.equal(challenge.body.accepts.length, 1);
  assert.equal(challenge.body.accepts[0].network, X402_CONFIG.network);
  assert.equal(challenge.body.accepts[0].payTo, X402_CONFIG.payTo);
});

test("Bazaar discovery metadata conforms to x402 Bazaar specification", () => {
  assert.ok(BAZAAR_DISCOVERY_METADATA.info);
  assert.equal(BAZAAR_DISCOVERY_METADATA.info.name, "PayGuard Security Service");
  assert.ok(Array.isArray(BAZAAR_DISCOVERY_METADATA.info.endpoints));
  assert.equal(BAZAAR_DISCOVERY_METADATA.info.endpoints.length, 2);
  assert.ok(BAZAAR_DISCOVERY_METADATA.schema);
  assert.equal(BAZAAR_DISCOVERY_METADATA.schema.$schema, "https://json-schema.org/draft/2020-12/schema");
});

test("x402 payment proof verification flow: unpaid -> 402 -> paid proof -> settled/simulated", async () => {
  // Step 1: Unpaid request (no header)
  const missingProof = await verifyPaymentProof(null, "https://api.payguard.example/api/analyze-url");
  assert.equal(missingProof.valid, false);

  // Step 2: Malformed proof
  const malformedProof = await verifyPaymentProof("invalid-header-without-signature", "https://api.payguard.example/api/analyze-url");
  assert.equal(malformedProof.valid, false);

  // Step 3: Valid payment signature header (simulated testnet verification)
  const validHeader = 'Payment-Signature sig="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"';
  const verified = await verifyPaymentProof(validHeader, "https://api.payguard.example/api/analyze-url");
  assert.equal(verified.valid, true);
  assert.equal(verified.mode, "mock_simulation");
  assert.equal(verified.settlement.settled, false); // explicitly false in simulation mode
  assert.equal(verified.settlement.simulated, true);
  assert.equal(verified.settlement.network, X402_CONFIG.network);
  assert.equal(verified.settlement.recipient, X402_CONFIG.payTo);

  // Step 4: Valid JSON payment payload
  const jsonHeader = JSON.stringify({
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: X402_CONFIG.network,
      amount: "1000",
      asset: X402_CONFIG.asset,
      payTo: X402_CONFIG.payTo
    },
    payload: {
      signature: "0xvalidSignatureString"
    }
  });
  const jsonVerified = await verifyPaymentProof(jsonHeader, "https://api.payguard.example/api/analyze-url");
  assert.equal(jsonVerified.valid, true);
  assert.equal(jsonVerified.settlement.simulated, true);
});

test("Security: invalid payment authorization or requirements mismatch is rejected", async () => {
  // Network mismatch
  const badNetwork = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: "eip155:1", amount: "1000", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: { signature: "0xvalid" }
  });
  const netRes = await verifyPaymentProof(badNetwork, "https://api.payguard.example/scan");
  assert.equal(netRes.valid, false);
  assert.ok(netRes.reason.includes("network"));

  // Amount underpayment
  const underpaid = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "500", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: { signature: "0xvalid" }
  });
  const underRes = await verifyPaymentProof(underpaid, "https://api.payguard.example/scan", "1000");
  assert.equal(underRes.valid, false);
  assert.ok(underRes.reason.includes("less than required"));

  // Wrong recipient
  const wrongPayTo = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "1000", asset: X402_CONFIG.asset, payTo: "0xAttackerAddress" },
    payload: { signature: "0xvalid" }
  });
  const recipRes = await verifyPaymentProof(wrongPayTo, "https://api.payguard.example/scan");
  assert.equal(recipRes.valid, false);
  assert.ok(recipRes.reason.includes("recipient"));

  // Missing signature
  const noSig = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "1000", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: {}
  });
  const noSigRes = await verifyPaymentProof(noSig, "https://api.payguard.example/scan");
  assert.equal(noSigRes.valid, false);
  assert.ok(noSigRes.reason.includes("signature"));
});

test("Security: malformed payment fields fail closed without throwing", async () => {
  const base = {
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: X402_CONFIG.network,
      amount: "1000",
      asset: X402_CONFIG.asset,
      payTo: X402_CONFIG.payTo
    },
    payload: { signature: "0xvalid" }
  };

  for (const amount of ["not-a-number", "-1", "1.5", "0x10", "", null, {}]) {
    const malformed = structuredClone(base);
    malformed.accepted.amount = amount;
    const result = await verifyPaymentProof(JSON.stringify(malformed), "https://api.payguard.example/scan");
    assert.equal(result.valid, false, `amount ${JSON.stringify(amount)} must be rejected`);
    assert.match(result.reason, /amount/i);
  }

  for (const field of ["asset", "payTo"]) {
    const malformed = structuredClone(base);
    malformed.accepted[field] = { toString: "not-an-address" };
    const result = await verifyPaymentProof(JSON.stringify(malformed), "https://api.payguard.example/scan");
    assert.equal(result.valid, false, `${field} with a non-string value must be rejected`);
    assert.match(result.reason, field === "asset" ? /asset/i : /recipient/i);
  }
});

test("Security: Facilitator /verify failure fails closed and live mode never falls back to mock", async () => {
  const validHeader = makeLivePaymentPayload();
  
  // Facilitator returns isValid: false
  const failedVerify = await verifyPaymentProof(validHeader, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) {
        return { ok: true, json: async () => ({ isValid: false, invalidReason: "invalid_exact_evm_payload_signature" }) };
      }
      return { ok: true, json: async () => ({ success: true, transaction: "0x123" }) };
    }
  });
  assert.equal(failedVerify.valid, false);
  assert.equal(failedVerify.settled, false);
  assert.ok(failedVerify.reason.includes("invalid_exact_evm_payload_signature"));

  // Facilitator network error in live mode fails closed without mock fallback
  const networkError = await verifyPaymentProof(validHeader, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async () => {
      throw new Error("Connection refused");
    }
  });
  assert.equal(networkError.valid, false);
  assert.equal(networkError.settled, false);
  assert.ok(networkError.reason.includes("network failure"));
});

test("Security: Settlement failure never produces a success response claiming payment was completed", async () => {
  const validHeader = makeLivePaymentPayload();

  // /verify succeeds (isValid: true) BUT /settle fails (success: false)
  const settleFail = await verifyPaymentProof(validHeader, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) {
        return { ok: true, json: async () => ({ isValid: true, payer: "0xPayer" }) };
      }
      if (url.endsWith("/settle")) {
        return { ok: true, json: async () => ({ success: false, errorReason: "insufficient_funds", transaction: "" }) };
      }
      throw new Error("Unknown URL");
    }
  });
  // Must NOT claim settled just because /verify returned isValid: true!
  assert.equal(settleFail.valid, false);
  assert.equal(settleFail.settled, false);
  assert.ok(settleFail.reason.includes("insufficient_funds"));
});

test("Security: Caller-supplied transaction hash is never accepted as proof of settlement", async () => {
  // A malicious client sends { txHash: "0xFakeTxHashClaimedByClient", signature: "0xSig" }
  const clientClaimedTx = JSON.stringify({
    x402Version: 2,
    accepted: { scheme: "exact", network: X402_CONFIG.network, amount: "1000", asset: X402_CONFIG.asset, payTo: X402_CONFIG.payTo },
    payload: { signature: "0xValidLookingSig" },
    txHash: "0xAttackerFabricatedTransactionHash"
  });

  // In mock/simulation mode, settled is strictly false
  const mockRes = await verifyPaymentProof(clientClaimedTx, "https://api.payguard.example/scan");
  assert.equal(mockRes.settlement.settled, false);
  assert.equal(mockRes.settlement.simulated, true);
  assert.equal(mockRes.settlement.transaction, undefined); // client's txHash must not be copied as proof

  // In live mode, settlement transaction comes strictly from facilitator's /settle response
  const livePayload = makeLivePaymentPayload();
  livePayload.txHash = "0xAttackerFabricatedTransactionHash";
  const liveRes = await verifyPaymentProof(livePayload, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) return { ok: true, json: async () => ({ isValid: true, payer: "0xUser" }) };
      if (url.endsWith("/settle")) return { ok: true, json: async () => ({ success: true, transaction: "0xFacilitatorConfirmedTxHash", network: "base-sepolia" }) };
      throw new Error("Unknown URL");
    }
  });
  assert.equal(liveRes.valid, true);
  assert.equal(liveRes.settlement.settled, true);
  assert.equal(liveRes.settlement.transaction, "0xFacilitatorConfirmedTxHash");
  assert.notEqual(liveRes.settlement.transaction, "0xAttackerFabricatedTransactionHash");
});


test("Security: same EIP-3009 authorization cannot be settled twice", async () => {
  const replayGuard = createInMemoryX402ReplayGuard();
  const payload = makeLivePaymentPayload();
  let verifyCalls = 0;
  let settleCalls = 0;
  const fetchImpl = async (url) => {
    if (url.endsWith("/verify")) {
      verifyCalls += 1;
      return { ok: true, json: async () => ({ isValid: true, payer: payload.payload.authorization.from }) };
    }
    settleCalls += 1;
    return { ok: true, json: async () => ({ success: true, transaction: "0xFacilitatorTx" }) };
  };
  const options = { liveFacilitator: true, facilitatorUrl: "https://mock-facilitator.example", fetchImpl, replayGuard };
  const first = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options);
  const replay = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options);
  assert.equal(first.valid, true);
  assert.equal(first.settlement.settled, true);
  assert.equal(replay.valid, false);
  assert.match(replay.reason, /duplicate|replay/i);
  assert.equal(verifyCalls, 1);
  assert.equal(settleCalls, 1);
});

test("Security: concurrent duplicate EIP-3009 requests reserve the nonce atomically", async () => {
  const replayGuard = createInMemoryX402ReplayGuard();
  const payload = makeLivePaymentPayload();
  let verifyCalls = 0;
  let settleCalls = 0;
  const fetchImpl = async (url) => {
    if (url.endsWith("/verify")) {
      verifyCalls += 1;
      await Promise.resolve();
      return { ok: true, json: async () => ({ isValid: true }) };
    }
    settleCalls += 1;
    return { ok: true, json: async () => ({ success: true, transaction: "0xConcurrentTx" }) };
  };
  const options = { liveFacilitator: true, facilitatorUrl: "https://mock-facilitator.example", fetchImpl, replayGuard };
  const results = await Promise.all([
    verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options),
    verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options)
  ]);
  assert.equal(results.filter((result) => result.valid).length, 1);
  assert.equal(results.filter((result) => !result.valid && /duplicate|replay/i.test(result.reason)).length, 1);
  assert.equal(verifyCalls, 1);
  assert.equal(settleCalls, 1);
});

test("Security: reservation is released after a definite facilitator verification rejection", async () => {
  const replayGuard = createInMemoryX402ReplayGuard();
  const payload = makeLivePaymentPayload();
  let shouldReject = true;
  const fetchImpl = async (url) => {
    if (url.endsWith("/verify")) {
      if (shouldReject) return { ok: true, json: async () => ({ isValid: false, invalidReason: "invalid_signature" }) };
      return { ok: true, json: async () => ({ isValid: true }) };
    }
    return { ok: true, json: async () => ({ success: true, transaction: "0xRetryTx" }) };
  };
  const options = { liveFacilitator: true, facilitatorUrl: "https://mock-facilitator.example", fetchImpl, replayGuard };
  const rejected = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options);
  shouldReject = false;
  const retried = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options);
  assert.equal(rejected.valid, false);
  assert.equal(retried.valid, true);
});

test("Security: ambiguous settlement transport failure keeps the authorization reserved", async () => {
  const replayGuard = createInMemoryX402ReplayGuard();
  const payload = makeLivePaymentPayload();
  const options = {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    replayGuard,
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) return { ok: true, json: async () => ({ isValid: true }) };
      throw new Error("connection dropped after broadcast");
    }
  };
  const first = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options);
  const retry = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", options);
  assert.equal(first.valid, false);
  assert.match(first.reason, /reserved pending reconciliation/i);
  assert.equal(retry.valid, false);
  assert.match(retry.reason, /duplicate|replay/i);
});

test("Security: live mode rejects missing EIP-3009 authorization before facilitator calls", async () => {
  const payload = makeLivePaymentPayload();
  delete payload.payload.authorization;
  let calls = 0;
  const result = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    fetchImpl: async () => { calls += 1; return { ok: true, json: async () => ({ isValid: true }) }; }
  });
  assert.equal(result.valid, false);
  assert.match(result.reason, /authorization/i);
  assert.equal(calls, 0);
});


test("Security: confirmed settlement is still reported accurately if settled-state persistence fails", async () => {
  const payload = makeLivePaymentPayload();
  const replayGuard = {
    async claim() { return { claimed: true, status: "pending" }; },
    async release() {},
    async markSettled() { throw new Error("storage unavailable"); }
  };
  const result = await verifyPaymentProof(payload, "https://api.payguard.example/scan", "1000", {
    liveFacilitator: true,
    facilitatorUrl: "https://mock-facilitator.example",
    replayGuard,
    fetchImpl: async (url) => {
      if (url.endsWith("/verify")) return { ok: true, json: async () => ({ isValid: true }) };
      return { ok: true, json: async () => ({ success: true, transaction: "0xConfirmedOnChainTx" }) };
    }
  });

  assert.equal(result.valid, true);
  assert.equal(result.settlement.settled, true);
  assert.equal(result.settlement.transaction, "0xConfirmedOnChainTx");
  assert.match(result.replayGuardWarning, /could not mark the reservation settled/i);
});

test("PayBox manifest and tool registration are intact", () => {
  assert.equal(payboxIntegration.manifest.id, "payguard");
  assert.ok(payboxIntegration.manifest.protocols.includes("x402"));
  assert.ok(payboxIntegration.manifest.protocols.includes("mcp"));
  assert.equal(payboxIntegration.plugin.tools.length, 12);
});


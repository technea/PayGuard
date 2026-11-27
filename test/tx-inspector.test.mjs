/**
 * Tests for src/tx-inspector.mjs
 * All RPC calls are mocked via fetchImpl — zero live requests.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { inspectTransactionHash, SUPPORTED_CHAIN_ID } from "../src/tx-inspector.mjs";
import { SELECTORS, UINT256_MAX } from "../src/calldata-inspector.mjs";

const VALID_HASH = "0x" + "a".repeat(64);
const CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const SPENDER  = "0x111111125421ca6dc452d289314280a0f8842a65";

function padAddress(addr) {
  return addr.toLowerCase().replace("0x", "").padStart(64, "0");
}
function padUint256(val) {
  return BigInt(val).toString(16).padStart(64, "0");
}

function makeFetch({ tx = null, receipt = null, txOk = true, receiptOk = true, status = 200, abortOnFirst = false } = {}) {
  let callIndex = 0;
  return async (url, options) => {
    callIndex++;
    if (abortOnFirst && callIndex === 1) {
      const err = new Error("Aborted");
      err.name = "AbortError";
      throw err;
    }
    const body = JSON.parse(options?.body || "{}");
    const isReceipt = body.method === "eth_getTransactionReceipt";
    const result = isReceipt ? receipt : tx;
    const ok = isReceipt ? receiptOk : txOk;
    return {
      ok,
      status: ok ? 200 : status,
      text: async () => JSON.stringify({ jsonrpc: "2.0", id: 1, result })
    };
  };
}

// ── Invalid hash format ───────────────────────────────────────────────────
test("1. Invalid tx hash format returns BLOCK", async () => {
  const result = await inspectTransactionHash({
    txHash: "0xinvalidhash",
    fetchImpl: async () => { throw new Error("should not be called"); }
  });
  assert.equal(result.verdict, "BLOCK");
  assert.ok(result.reasonCodes.includes("INVALID_TX_HASH"));
  assert.equal(result.simulationPerformed, false);
});

test("2. Missing tx hash (non-string) returns BLOCK", async () => {
  const result = await inspectTransactionHash({
    txHash: null,
    fetchImpl: async () => { throw new Error("should not be called"); }
  });
  assert.equal(result.verdict, "BLOCK");
  assert.ok(result.reasonCodes.includes("INVALID_TX_HASH"));
});

// ── Unsupported chain ─────────────────────────────────────────────────────
test("3. Unsupported chain returns UNVERIFIED with UNSUPPORTED_CHAIN", async () => {
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: "1",
    fetchImpl: async () => { throw new Error("should not be called"); }
  });
  assert.equal(result.verdict, "UNVERIFIED");
  assert.ok(result.reasonCodes.includes("UNSUPPORTED_CHAIN"));
  assert.equal(result.simulationPerformed, false);
});

// ── TX not found ──────────────────────────────────────────────────────────
test("4. Transaction hash not found on chain returns TX_NOT_FOUND", async () => {
  const fetchImpl = makeFetch({ tx: null, receipt: null });
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verdict, "UNVERIFIED");
  assert.ok(result.reasonCodes.includes("TX_NOT_FOUND"));
  assert.equal(result.simulationPerformed, false);
});

// ── RPC error ────────────────────────────────────────────────────────────
test("5. RPC HTTP error returns UNVERIFIED", async () => {
  const fetchImpl = makeFetch({ txOk: false, status: 500 });
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verdict, "UNVERIFIED");
  assert.equal(result.simulationPerformed, false);
});

// ── Request timeout ──────────────────────────────────────────────────────
test("6. RPC timeout returns UNVERIFIED with REQUEST_TIMEOUT", async () => {
  const fetchImpl = async () => {
    const err = new Error("Aborted");
    err.name = "AbortError";
    throw err;
  };
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl,
    timeoutMs: 1
  });
  assert.equal(result.verdict, "UNVERIFIED");
  assert.ok(result.reasonCodes.includes("REQUEST_TIMEOUT"));
  assert.equal(result.simulationPerformed, false);
});

// ── Valid tx with no calldata (native ETH transfer) ──────────────────────
test("7. Valid native ETH transfer returns PASS", async () => {
  const tx = {
    hash: VALID_HASH,
    from: "0xaaaa000000000000000000000000000000000001",
    to: "0xbbbb000000000000000000000000000000000002",
    value: "0x38d7ea4c68000",
    input: "0x"
  };
  const fetchImpl = makeFetch({ tx, receipt: { status: "0x1", logs: [] } });
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verdict, "PASS");
  assert.equal(result.receiptStatus, "CONFIRMED");
  assert.equal(result.simulationPerformed, false);
  assert.equal(result.decodingStatus, "DECODED");
});

// ── APPROVE with unlimited amount in receipt logs ─────────────────────────
test("8. Receipt unlimited ERC-20 Approval event sets RECEIPT_UNLIMITED_APPROVAL_EVENT", async () => {
  const tx = {
    hash: VALID_HASH,
    from: "0xaaaa",
    to: CONTRACT,
    value: "0x0",
    input: SELECTORS.ERC20_APPROVE + padAddress(SPENDER) + padUint256(UINT256_MAX)
  };
  // Simulate approval log in receipt
  const ERC20_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
  const ownerTopic = "0x000000000000000000000000aaaa000000000000000000000000000000000000";
  const spenderTopic = "0x000000000000000000000000" + SPENDER.replace("0x", "");
  const receipt = {
    status: "0x1",
    logs: [{
      address: CONTRACT,
      topics: [ERC20_APPROVAL_TOPIC, ownerTopic, spenderTopic],
      data: "0x" + "f".repeat(64) // uint256 max
    }]
  };
  const fetchImpl = makeFetch({ tx, receipt });
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl
  });
  assert.ok(result.reasonCodes.includes("RECEIPT_UNLIMITED_APPROVAL_EVENT"),
    `Expected RECEIPT_UNLIMITED_APPROVAL_EVENT in ${JSON.stringify(result.reasonCodes)}`);
  assert.equal(result.logEvents.some(e => e.type === "ERC20_APPROVAL" && e.isUnlimited), true);
  assert.equal(result.simulationPerformed, false);
});

// ── Contract deployment tx ────────────────────────────────────────────────
test("9. Contract creation tx (to is null) returns REVIEW", async () => {
  const tx = {
    hash: VALID_HASH,
    from: "0xaaaa",
    to: null,
    value: "0x0",
    input: "0x60806040" // some bytecode
  };
  const fetchImpl = makeFetch({ tx, receipt: { status: "0x1", logs: [] } });
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl
  });
  assert.ok(["REVIEW", "BLOCK"].includes(result.verdict));
  assert.ok(result.reasonCodes.includes("CONTRACT_CREATION_TX"));
  assert.equal(result.simulationPerformed, false);
});

// ── simulationPerformed is always false ──────────────────────────────────
test("10. simulationPerformed is always false regardless of outcome", async () => {
  const inputs = [
    { txHash: "0xinvalid" },
    { txHash: VALID_HASH, chainId: "99999" },
    { txHash: VALID_HASH, chainId: SUPPORTED_CHAIN_ID, fetchImpl: makeFetch({ tx: null }) }
  ];
  for (const input of inputs) {
    const result = await inspectTransactionHash(input);
    assert.equal(result.simulationPerformed, false,
      `simulationPerformed must be false, got ${result.simulationPerformed} for input: ${JSON.stringify(input)}`);
  }
});

// ── Unknown calldata selector decodingStatus ─────────────────────────────
test("11. Unknown calldata selector sets decodingStatus based on logs", async () => {
  const tx = {
    hash: VALID_HASH,
    from: "0xaaaa",
    to: CONTRACT,
    value: "0x0",
    input: "0xdeadbeef" + "00".repeat(28) // unknown selector
  };
  const fetchImpl = makeFetch({ tx, receipt: { status: "0x1", logs: [] } });
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl
  });
  // No logs → UNSUPPORTED; with logs would be PARTIAL
  assert.equal(result.decodingStatus, "UNSUPPORTED");
  assert.equal(result.simulationPerformed, false);
});

// ── Reverted tx ──────────────────────────────────────────────────────────
test("12. Reverted transaction shows receiptStatus REVERTED", async () => {
  const tx = {
    hash: VALID_HASH,
    from: "0xaaaa",
    to: CONTRACT,
    value: "0x0",
    input: "0x"
  };
  const receipt = { status: "0x0", logs: [] };
  const fetchImpl = makeFetch({ tx, receipt });
  const result = await inspectTransactionHash({
    txHash: VALID_HASH,
    chainId: SUPPORTED_CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.receiptStatus, "REVERTED");
  assert.equal(result.simulationPerformed, false);
});


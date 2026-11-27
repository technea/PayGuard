/**
 * Tests for src/contract-verification.mjs
 * All network calls are mocked via fetchImpl — zero live requests.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { checkContractVerification } from "../src/contract-verification.mjs";

const VALID_ADDRESS = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"; // Base USDC
const CHAIN_ID = "8453";

// ── Sourcify v2 success (exact match) ──────────────────────────────────────
test("1. Sourcify exact_match returns VERIFIED", async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({
      address: VALID_ADDRESS,
      chainId: CHAIN_ID,
      match: "exact_match",
      verifiedAt: "2024-01-01T00:00:00Z",
      deployment: { blockNumber: 1000 }
    })
  });
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verified, true);
  assert.equal(result.verificationStatus, "VERIFIED");
  assert.ok(["VERIFIED", "PASS"].includes(result.status));
  assert.equal(result.source, "sourcify_v2");
});

// ── Sourcify partial match also counts as VERIFIED ─────────────────────────
test("2. Sourcify partial_match returns VERIFIED", async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({
      address: VALID_ADDRESS,
      chainId: CHAIN_ID,
      match: "partial_match",
      verifiedAt: "2024-02-01T00:00:00Z"
    })
  });
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verified, true);
  assert.equal(result.verificationStatus, "VERIFIED");
});

// ── Sourcify 404 not found → UNVERIFIED ────────────────────────────────────
test("3. Sourcify 404 returns UNVERIFIED with CONTRACT_SOURCE_UNVERIFIED", async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 404,
    text: async () => "Not Found"
  });
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verified, false);
  assert.equal(result.verificationStatus, "UNVERIFIED");
  assert.ok(result.reasonCodes.includes("CONTRACT_SOURCE_UNVERIFIED"));
  // Critical invariant: unverified never becomes MALICIOUS or BLOCK
  assert.notEqual(result.status, "MALICIOUS");
  if (result.verdict !== undefined) {
    assert.notEqual(result.verdict, "BLOCK");
  }
});

// ── Sourcify 429 rate-limited → UNVERIFIED ────────────────────────────────
test("4. Sourcify 429 rate-limit returns UNVERIFIED with RATE_LIMITED", async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 429,
    text: async () => "Too Many Requests"
  });
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verified, false);
  assert.equal(result.verificationStatus, "UNVERIFIED");
  assert.ok(result.reasonCodes.includes("RATE_LIMITED"));
});

// ── Request timeout → UNVERIFIED ───────────────────────────────────────────
test("5. Request timeout returns UNVERIFIED with REQUEST_TIMEOUT", async () => {
  const fetchImpl = async () => {
    const err = new Error("Aborted");
    err.name = "AbortError";
    throw err;
  };
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl,
    timeoutMs: 1
  });
  assert.equal(result.verified, false);
  assert.equal(result.verificationStatus, "UNVERIFIED");
  assert.ok(result.reasonCodes.includes("REQUEST_TIMEOUT"));
});

// ── Invalid address → ERROR ────────────────────────────────────────────────
test("6. Invalid contract address returns ERROR", async () => {
  const fetchImpl = async () => { throw new Error("should not be called"); };
  const result = await checkContractVerification({
    contractAddress: "not-an-address",
    chainId: CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verified, false);
  assert.equal(result.status, "ERROR");
  assert.equal(result.verificationStatus, "NOT_CHECKED");
  assert.ok(result.reasonCodes.includes("INVALID_CONTRACT_ADDRESS"));
});

// ── Unsupported chain → NOT_CHECKED ───────────────────────────────────────
test("7. Unsupported chain ID returns NOT_CHECKED", async () => {
  const fetchImpl = async () => { throw new Error("should not be called"); };
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: "1", // Ethereum mainnet — not supported by this integration
    fetchImpl
  });
  assert.equal(result.verified, false);
  assert.ok(result.reasonCodes.includes("UNSUPPORTED_CHAIN"));
});

// ── Oversized response → UNVERIFIED ──────────────────────────────────────
test("8. Oversized Sourcify response returns UNVERIFIED", async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    text: async () => "x".repeat(300 * 1024) // > 256 KB
  });
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verified, false);
  assert.equal(result.verificationStatus, "UNVERIFIED");
});

// ── Etherscan fallback with API key ──────────────────────────────────────
test("9. Etherscan fallback returns VERIFIED when Sourcify 404 and key present", async () => {
  let callCount = 0;
  const fetchImpl = async (url) => {
    callCount++;
    // First call: Sourcify → 404
    if (typeof url === "string" && url.includes("sourcify.dev")) {
      return { ok: false, status: 404, text: async () => "Not Found" };
    }
    // Second call: Etherscan/BaseScan → success
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        status: "1",
        message: "OK",
        result: [{ SourceCode: "pragma solidity", ContractName: "FakeToken", ABI: "[]" }]
      })
    };
  };
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl,
    etherscanApiKey: "FAKE_KEY_FOR_TESTING"
  });
  assert.equal(result.verified, true);
  assert.equal(result.verificationStatus, "VERIFIED");
  assert.equal(callCount, 2);
});

// ── Sourcify 404 + no Etherscan key → UNVERIFIED ─────────────────────────
test("10. Sourcify 404 and no Etherscan key returns UNVERIFIED", async () => {
  const fetchImpl = async () => ({
    ok: false,
    status: 404,
    text: async () => "Not Found"
  });
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl
    // No etherscanApiKey
  });
  assert.equal(result.verified, false);
  assert.equal(result.verificationStatus, "UNVERIFIED");
});

// ── Critical invariant: unverified ≠ MALICIOUS ────────────────────────────
test("11. verified===false never yields status===MALICIOUS or verdict===BLOCK from missing source", async () => {
  const scenarios = [
    { ok: false, status: 404 },
    { ok: false, status: 429 },
    { ok: false, status: 500 }
  ];
  for (const scenario of scenarios) {
    const fetchImpl = async () => ({ ...scenario, text: async () => "error" });
    const result = await checkContractVerification({
      contractAddress: VALID_ADDRESS,
      chainId: CHAIN_ID,
      fetchImpl
    });
    assert.equal(result.verified, false, `verified must be false for status ${scenario.status}`);
    assert.notEqual(result.status, "MALICIOUS", `status must not be MALICIOUS for HTTP ${scenario.status}`);
    if (result.verdict !== undefined) {
      assert.notEqual(result.verdict, "BLOCK", `verdict must not be BLOCK for unverified source (HTTP ${scenario.status})`);
    }
  }
});

// ── malformed JSON ────────────────────────────────────────────────────────
test("12. Malformed JSON from Sourcify returns UNVERIFIED", async () => {
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    text: async () => "not json {"
  });
  const result = await checkContractVerification({
    contractAddress: VALID_ADDRESS,
    chainId: CHAIN_ID,
    fetchImpl
  });
  assert.equal(result.verified, false);
  assert.equal(result.verificationStatus, "UNVERIFIED");
});

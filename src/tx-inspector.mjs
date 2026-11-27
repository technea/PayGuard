/**
 * PayGuard Read-Only Transaction Hash Inspector (Base Mainnet 8453)
 *
 * Fetches transaction & receipt data via JSON-RPC (`eth_getTransactionByHash` and
 * `eth_getTransactionReceipt`), delegates calldata decoding to `inspectCalldata`,
 * and inspects standard ERC-20 Approval / Transfer event logs.
 *
 * Security boundaries:
 * - Read-only only; performs zero signing, broadcasting, or simulation claims.
 * - Clearly marks unsupported or partially decoded transactions.
 */

import { inspectCalldata, UINT256_MAX } from "./calldata-inspector.mjs";

export const DEFAULT_BASE_RPC_URL = "https://mainnet.base.org";
export const SUPPORTED_CHAIN_ID = "8453";
export const DEFAULT_TX_TIMEOUT_MS = 5000;
export const MAX_RPC_RESPONSE_CHARS = 256 * 1024;

const TX_HASH_REGEX = /^0x[0-9a-fA-F]{64}$/;
const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ERC20_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";

function topicToAddress(topic) {
  if (typeof topic !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(topic)) return null;
  return "0x" + topic.slice(26).toLowerCase();
}

async function rpcCall(rpcUrl, method, params, fetchImpl, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: controller.signal
    });
    if (!response?.ok) {
      return { ok: false, reason: response?.status === 429 ? "RATE_LIMITED" : "RPC_HTTP_ERROR", result: null };
    }
    const raw = await response.text();
    if (typeof raw !== "string" || raw.length > MAX_RPC_RESPONSE_CHARS) {
      return { ok: false, reason: "OVERSIZED_RESPONSE", result: null };
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { ok: false, reason: "MALFORMED_JSON", result: null };
    }
    if (parsed?.error) {
      return { ok: false, reason: "RPC_ERROR", result: null };
    }
    return { ok: true, reason: null, result: parsed?.result ?? null };
  } catch (error) {
    return { ok: false, reason: error?.name === "AbortError" ? "REQUEST_TIMEOUT" : "NETWORK_ERROR", result: null };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Inspect an on-chain Base transaction hash using read-only RPC + calldata decoding.
 *
 * @param {object} params
 * @param {string} params.txHash
 * @param {string|number} [params.chainId="8453"]
 * @param {object} [params.policy]
 * @param {Function} [params.fetchImpl]
 * @param {string} [params.rpcUrl]
 * @param {number} [params.timeoutMs]
 * @returns {Promise<object>}
 */
export async function inspectTransactionHash({
  txHash,
  chainId = SUPPORTED_CHAIN_ID,
  policy = {},
  fetchImpl = globalThis.fetch,
  rpcUrl = process.env.BASE_RPC_URL || DEFAULT_BASE_RPC_URL,
  timeoutMs = DEFAULT_TX_TIMEOUT_MS
} = {}) {
  const normChain = String(chainId ?? SUPPORTED_CHAIN_ID).replace(/^eip155:/, "").trim() || SUPPORTED_CHAIN_ID;
  if (normChain !== SUPPORTED_CHAIN_ID) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: normChain,
      txHash: typeof txHash === "string" ? txHash.toLowerCase() : null,
      decodingStatus: "UNSUPPORTED",
      simulationPerformed: false,
      findings: [{
        code: "UNSUPPORTED_CHAIN",
        severity: "medium",
        message: `Transaction inspection supports Base Mainnet (8453); received '${normChain}'.`
      }],
      reasonCodes: ["UNSUPPORTED_CHAIN"],
      dataStatus: "UNAVAILABLE"
    };
  }

  if (typeof txHash !== "string" || !TX_HASH_REGEX.test(txHash)) {
    return {
      verdict: "BLOCK",
      riskLevel: "HIGH",
      chainId: SUPPORTED_CHAIN_ID,
      txHash: typeof txHash === "string" ? txHash : null,
      decodingStatus: "UNSUPPORTED",
      simulationPerformed: false,
      findings: [{
        code: "INVALID_TX_HASH",
        severity: "high",
        message: "Transaction hash must be a 32-byte 0x-prefixed hex string."
      }],
      reasonCodes: ["INVALID_TX_HASH"],
      dataStatus: "UNAVAILABLE"
    };
  }

  const normHash = txHash.toLowerCase();
  if (typeof fetchImpl !== "function") {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: SUPPORTED_CHAIN_ID,
      txHash: normHash,
      decodingStatus: "UNSUPPORTED",
      simulationPerformed: false,
      findings: [{
        code: "FETCH_UNAVAILABLE",
        severity: "medium",
        message: "Fetch implementation is unavailable for transaction lookup."
      }],
      reasonCodes: ["FETCH_UNAVAILABLE"],
      dataStatus: "UNAVAILABLE"
    };
  }

  const safeTimeout = Number.isSafeInteger(timeoutMs) && timeoutMs > 0
    ? Math.min(timeoutMs, 15_000)
    : DEFAULT_TX_TIMEOUT_MS;

  const [txRes, receiptRes] = await Promise.all([
    rpcCall(rpcUrl, "eth_getTransactionByHash", [normHash], fetchImpl, safeTimeout),
    rpcCall(rpcUrl, "eth_getTransactionReceipt", [normHash], fetchImpl, safeTimeout)
  ]);

  if (!txRes.ok) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: SUPPORTED_CHAIN_ID,
      txHash: normHash,
      decodingStatus: "UNSUPPORTED",
      simulationPerformed: false,
      findings: [{
        code: txRes.reason,
        severity: "medium",
        message: `Failed to fetch transaction from Base RPC (${txRes.reason}).`
      }],
      reasonCodes: [txRes.reason],
      dataStatus: "UNAVAILABLE"
    };
  }

  if (!txRes.result) {
    return {
      verdict: "UNVERIFIED",
      riskLevel: "UNKNOWN",
      chainId: SUPPORTED_CHAIN_ID,
      txHash: normHash,
      decodingStatus: "UNSUPPORTED",
      simulationPerformed: false,
      findings: [{
        code: "TX_NOT_FOUND",
        severity: "medium",
        message: "Transaction hash was not found on Base Mainnet."
      }],
      reasonCodes: ["TX_NOT_FOUND"],
      dataStatus: "UNAVAILABLE"
    };
  }

  const tx = txRes.result;
  const receipt = receiptRes.ok ? receiptRes.result : null;
  const calldataResult = tx.to
    ? inspectCalldata({ to: tx.to, value: tx.value || "0x0", data: tx.input || "0x" }, policy)
    : {
        verdict: "REVIEW",
        riskLevel: "MEDIUM",
        operation: "CONTRACT_DEPLOYMENT",
        reasons: ["CONTRACT_CREATION_TX"],
        checks: [{ id: "tx_type", status: "WARN", detail: "Transaction creates a new contract (to is null)." }],
        details: null
      };

  const logEvents = [];
  const findings = [];
  const reasonCodes = [...(calldataResult.reasons || [])];

  if (Array.isArray(calldataResult.reasons)) {
    for (const reason of calldataResult.reasons) {
      findings.push({
        code: reason,
        severity: calldataResult.verdict === "BLOCK" ? "high" : "medium",
        message: `Calldata inspection flagged: ${reason}`
      });
    }
  }

  if (receipt && Array.isArray(receipt.logs)) {
    for (const log of receipt.logs.slice(0, 50)) {
      const topic0 = typeof log?.topics?.[0] === "string" ? log.topics[0].toLowerCase() : "";
      if (topic0 === ERC20_APPROVAL_TOPIC) {
        const owner = topicToAddress(log.topics[1]);
        const spender = topicToAddress(log.topics[2]);
        let amount = null;
        try {
          if (typeof log.data === "string" && /^0x[0-9a-fA-F]{64}$/.test(log.data)) {
            amount = BigInt(log.data);
          }
        } catch {
          amount = null;
        }
        const isUnlimited = amount === UINT256_MAX;
        logEvents.push({
          type: "ERC20_APPROVAL",
          tokenAddress: typeof log.address === "string" ? log.address.toLowerCase() : null,
          owner,
          spender,
          amount: amount !== null ? amount.toString() : null,
          isUnlimited
        });
        if (isUnlimited) {
          reasonCodes.push("RECEIPT_UNLIMITED_APPROVAL_EVENT");
          findings.push({
            code: "RECEIPT_UNLIMITED_APPROVAL_EVENT",
            severity: "high",
            message: `Receipt emitted an unlimited ERC-20 Approval event for spender ${spender}.`
          });
        }
      } else if (topic0 === ERC20_TRANSFER_TOPIC) {
        logEvents.push({
          type: "ERC20_TRANSFER",
          tokenAddress: typeof log.address === "string" ? log.address.toLowerCase() : null,
          from: topicToAddress(log.topics[1]),
          to: topicToAddress(log.topics[2])
        });
      }
    }
  }

  const decodingStatus = calldataResult.operation === "UNKNOWN_OPERATION"
    ? (logEvents.length > 0 ? "PARTIAL" : "UNSUPPORTED")
    : "DECODED";

  const hasHigh = findings.some(f => f.severity === "high" || f.severity === "critical");
  const verdict = calldataResult.verdict === "BLOCK" ? "BLOCK" : (hasHigh || calldataResult.verdict === "REVIEW" ? "REVIEW" : "PASS");
  const riskLevel = verdict === "BLOCK" ? "HIGH" : verdict === "REVIEW" ? "MEDIUM" : "LOW";

  return {
    verdict,
    riskLevel,
    chainId: SUPPORTED_CHAIN_ID,
    txHash: normHash,
    from: typeof tx.from === "string" ? tx.from.toLowerCase() : null,
    to: typeof tx.to === "string" ? tx.to.toLowerCase() : null,
    receiptStatus: receipt ? (receipt.status === "0x1" ? "CONFIRMED" : "REVERTED") : "UNKNOWN",
    operation: calldataResult.operation,
    decodingStatus,
    simulationPerformed: false,
    calldata: calldataResult,
    logEvents,
    findings,
    reasonCodes: [...new Set(reasonCodes)],
    dataStatus: "FRESH"
  };
}

export default inspectTransactionHash;


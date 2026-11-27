/**
 * PayGuard Contract Verification Adapter (Base Mainnet 8453)
 *
 * Read-only contract source verification lookup using:
 * 1. Primary: Sourcify API v2 (https://sourcify.dev/server/v2/contract/8453/{address})
 * 2. Fallback: Etherscan API v2 (https://api.etherscan.io/v2/api?chainid=8453&module=contract&action=getsourcecode)
 *    when ETHERSCAN_API_KEY or BASESCAN_API_KEY is configured.
 *
 * Security invariants:
 * - Unverified contracts are NOT automatically malicious.
 * - Unavailable verification data is NEVER treated as proof of safety.
 * - API keys are never placed in error messages or logs.
 */

export const SOURCIFY_V2_BASE_URL = "https://sourcify.dev/server/v2/contract";
export const ETHERSCAN_V2_API_URL = "https://api.etherscan.io/v2/api";
export const SUPPORTED_CHAIN_ID = "8453";
export const DEFAULT_VERIFICATION_TIMEOUT_MS = 4000;
export const MAX_VERIFICATION_RESPONSE_CHARS = 128 * 1024;

const ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/;

function normalizeChainId(chainId) {
  if (chainId === undefined || chainId === null) return SUPPORTED_CHAIN_ID;
  if (typeof chainId === "number") return String(chainId);
  if (typeof chainId === "string") {
    const trimmed = chainId.trim();
    if (!trimmed) return SUPPORTED_CHAIN_ID;
    return trimmed.startsWith("eip155:") ? trimmed.slice(7) : trimmed;
  }
  return "";
}

function buildResult(fields) {
  return {
    chainId: SUPPORTED_CHAIN_ID,
    contractAddress: null,
    status: "UNVERIFIED",
    verificationStatus: "UNVERIFIED",
    dataStatus: "UNAVAILABLE",
    verified: false,
    matchType: null,
    contractName: null,
    source: null,
    reasonCodes: [],
    findings: [],
    timestamp: Date.now(),
    ...fields
  };
}

async function fetchJsonWithLimits(url, fetchImpl, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal
    });
    const rawText = await response.text();
    if (typeof rawText !== "string" || rawText.length > MAX_VERIFICATION_RESPONSE_CHARS) {
      return { ok: false, reason: "OVERSIZED_RESPONSE", httpStatus: response?.status ?? 0, data: null };
    }
    let data = null;
    if (response?.ok && rawText.trim().length > 0) {
      try {
        data = JSON.parse(rawText);
      } catch {
        return { ok: false, reason: "MALFORMED_JSON", httpStatus: response?.status ?? 0, data: null };
      }
    }
    return {
      ok: Boolean(response?.ok),
      httpStatus: Number.isInteger(response?.status) ? response.status : 0,
      reason: null,
      data
    };
  } catch (error) {
    return {
      ok: false,
      httpStatus: 0,
      reason: error?.name === "AbortError" ? "REQUEST_TIMEOUT" : "NETWORK_ERROR",
      data: null
    };
  } finally {
    clearTimeout(timer);
  }
}

function mapHttpReason(httpStatus) {
  if (httpStatus === 401 || httpStatus === 403) return "AUTH_ERROR";
  if (httpStatus === 429) return "RATE_LIMITED";
  if (httpStatus >= 500) return "UPSTREAM_ERROR";
  return "HTTP_ERROR";
}

/**
 * Check contract source verification on Base Mainnet (8453).
 *
 * @param {object} params
 * @param {string} params.contractAddress
 * @param {string|number} [params.chainId="8453"]
 * @param {Function} [params.fetchImpl]
 * @param {number} [params.timeoutMs]
 * @param {string} [params.etherscanApiKey]
 * @returns {Promise<object>}
 */
export async function checkContractVerification({
  contractAddress,
  chainId = SUPPORTED_CHAIN_ID,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_VERIFICATION_TIMEOUT_MS,
  etherscanApiKey = process.env.ETHERSCAN_API_KEY || process.env.BASESCAN_API_KEY
} = {}) {
  const normChain = normalizeChainId(chainId);
  if (normChain !== SUPPORTED_CHAIN_ID) {
    return buildResult({
      chainId: normChain || null,
      contractAddress: typeof contractAddress === "string" ? contractAddress.toLowerCase() : null,
      status: "UNVERIFIED",
      verificationStatus: "NOT_CHECKED",
      dataStatus: "UNAVAILABLE",
      reasonCodes: ["UNSUPPORTED_CHAIN"],
      findings: [{
        code: "UNSUPPORTED_CHAIN",
        severity: "medium",
        message: `Contract verification currently supports Base Mainnet (8453); received '${normChain || "empty"}'.`
      }]
    });
  }

  if (typeof contractAddress !== "string" || !ADDRESS_REGEX.test(contractAddress)) {
    return buildResult({
      contractAddress: typeof contractAddress === "string" ? contractAddress : null,
      status: "ERROR",
      verificationStatus: "NOT_CHECKED",
      dataStatus: "UNAVAILABLE",
      reasonCodes: ["INVALID_CONTRACT_ADDRESS"],
      findings: [{
        code: "INVALID_CONTRACT_ADDRESS",
        severity: "medium",
        message: "Contract address must be a valid 20-byte EVM hex address."
      }]
    });
  }

  const normAddress = contractAddress.toLowerCase();
  if (typeof fetchImpl !== "function") {
    return buildResult({
      contractAddress: normAddress,
      status: "ERROR",
      verificationStatus: "NOT_CHECKED",
      dataStatus: "UNAVAILABLE",
      reasonCodes: ["FETCH_UNAVAILABLE"],
      findings: [{
        code: "FETCH_UNAVAILABLE",
        severity: "medium",
        message: "Fetch implementation is unavailable for contract verification."
      }]
    });
  }

  const safeTimeout = Number.isSafeInteger(timeoutMs) && timeoutMs > 0
    ? Math.min(timeoutMs, 15_000)
    : DEFAULT_VERIFICATION_TIMEOUT_MS;

  // 1. Primary: Sourcify v2
  const sourcifyUrl = `${SOURCIFY_V2_BASE_URL}/${SUPPORTED_CHAIN_ID}/${normAddress}`;
  const sourcifyRes = await fetchJsonWithLimits(sourcifyUrl, fetchImpl, safeTimeout);

  if (sourcifyRes.ok && sourcifyRes.data && typeof sourcifyRes.data === "object") {
    const match = sourcifyRes.data.match || sourcifyRes.data.runtimeMatch || sourcifyRes.data.creationMatch || null;
    if (match === "exact_match" || match === "match" || match === "partial_match") {
      return buildResult({
        contractAddress: normAddress,
        status: "VERIFIED",
        verificationStatus: "VERIFIED",
        dataStatus: "FRESH",
        verified: true,
        matchType: match,
        verifiedAt: typeof sourcifyRes.data.verifiedAt === "string" ? sourcifyRes.data.verifiedAt : null,
        source: "sourcify_v2",
        reasonCodes: ["CONTRACT_SOURCE_VERIFIED"],
        findings: []
      });
    }
  }

  const sourcifyNotFound = sourcifyRes.httpStatus === 404;
  const sourcifyErrorCode = sourcifyRes.reason || (!sourcifyRes.ok && !sourcifyNotFound ? mapHttpReason(sourcifyRes.httpStatus) : null);

  // 2. Fallback: Etherscan v2 (if API key configured)
  if (typeof etherscanApiKey === "string" && etherscanApiKey.trim().length > 0) {
    const url = new URL(ETHERSCAN_V2_API_URL);
    url.searchParams.set("chainid", SUPPORTED_CHAIN_ID);
    url.searchParams.set("module", "contract");
    url.searchParams.set("action", "getsourcecode");
    url.searchParams.set("address", normAddress);
    url.searchParams.set("apikey", etherscanApiKey.trim());

    const ethRes = await fetchJsonWithLimits(url.toString(), fetchImpl, safeTimeout);
    if (ethRes.ok && ethRes.data && ethRes.data.status === "1" && Array.isArray(ethRes.data.result) && ethRes.data.result.length > 0) {
      const entry = ethRes.data.result[0];
      const hasSource = typeof entry?.SourceCode === "string" && entry.SourceCode.trim().length > 0;
      if (hasSource) {
        return buildResult({
          contractAddress: normAddress,
          status: "VERIFIED",
          verificationStatus: "VERIFIED",
          dataStatus: "FRESH",
          verified: true,
          matchType: "etherscan_verified",
          contractName: typeof entry.ContractName === "string" && entry.ContractName ? entry.ContractName : null,
          source: "etherscan_v2",
          reasonCodes: ["CONTRACT_SOURCE_VERIFIED"],
          findings: []
        });
      }
      return buildResult({
        contractAddress: normAddress,
        status: "UNVERIFIED",
        verificationStatus: "UNVERIFIED",
        dataStatus: "FRESH",
        verified: false,
        source: "etherscan_v2",
        reasonCodes: ["CONTRACT_SOURCE_UNVERIFIED"],
        findings: [{
          code: "CONTRACT_SOURCE_UNVERIFIED",
          severity: "info",
          message: "Contract source code is not verified on Sourcify or Etherscan. Unverified status is not proof of malice."
        }]
      });
    }
  }

  if (sourcifyNotFound) {
    return buildResult({
      contractAddress: normAddress,
      status: "UNVERIFIED",
      verificationStatus: "UNVERIFIED",
      dataStatus: "FRESH",
      verified: false,
      source: "sourcify_v2",
      reasonCodes: ["CONTRACT_SOURCE_UNVERIFIED"],
      findings: [{
        code: "CONTRACT_SOURCE_UNVERIFIED",
        severity: "info",
        message: "Contract source code is not verified in Sourcify. Unverified status is not proof of malice."
      }]
    });
  }

  const code = sourcifyErrorCode || "VERIFICATION_UNAVAILABLE";
  return buildResult({
    contractAddress: normAddress,
    status: "UNVERIFIED",
    verificationStatus: "UNVERIFIED",
    dataStatus: "UNAVAILABLE",
    verified: false,
    source: "sourcify_v2",
    reasonCodes: [code],
    findings: [{
      code,
      severity: "medium",
      message: "Contract verification provider was unavailable or returned an unusable response."
    }]
  });
}

export default checkContractVerification;


/**
 * o1 Alpha Token Discovery client.
 *
 * Read-only public endpoint. This module only discovers contract addresses;
 * it does not infer token safety or execute trades.
 */

export const O1_ALPHA_API_URL = "https://api.o1.exchange/api/v1/alpha-tokens";
export const O1_ALPHA_MAX_ADDRESSES = 1_000;
export const O1_ALPHA_DEFAULT_TIMEOUT_MS = 8_000;

const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const MAX_RESPONSE_CHARS = 256_000;

function normalizeNetworkId(value) {
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return String(value);
  }
  if (typeof value === "string" && /^[1-9][0-9]*$/.test(value.trim())) {
    const parsed = Number(value.trim());
    if (Number.isSafeInteger(parsed) && parsed > 0) return String(parsed);
  }
  return null;
}

function failure(status, networkId, reason, extra = {}) {
  return {
    status,
    networkId: networkId ?? null,
    addresses: [],
    count: 0,
    reason,
    ...extra
  };
}

/**
 * Fetch the ranked o1 Alpha contract-address list for one network.
 *
 * @param {{ networkId: number|string }} input
 * @param {{ fetchImpl?: Function, timeoutMs?: number }} options
 * @returns {Promise<object>} Structured discovery result; never a safety verdict.
 */
export async function fetchO1AlphaTokenAddresses(input, options = {}) {
  const networkId = normalizeNetworkId(input?.networkId);
  if (!networkId) {
    return failure(
      "ERROR",
      null,
      "INVALID_NETWORK_ID",
      { message: "networkId must be a positive safe integer." }
    );
  }

  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = Number.isSafeInteger(options.timeoutMs) && options.timeoutMs > 0
    ? Math.min(options.timeoutMs, 30_000)
    : O1_ALPHA_DEFAULT_TIMEOUT_MS;

  if (typeof fetchImpl !== "function") {
    return failure("UNVERIFIED", networkId, "FETCH_UNAVAILABLE");
  }

  const url = new URL(O1_ALPHA_API_URL);
  url.searchParams.set("networkId", networkId);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(url.toString(), {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal
    });

    if (!response?.ok) {
      const httpStatus = Number.isInteger(response?.status) ? response.status : 0;
      if (httpStatus === 429) {
        return failure("UNVERIFIED", networkId, "RATE_LIMITED", {
          httpStatus,
          retryAfter: response.headers?.get?.("retry-after") ?? null
        });
      }
      if (httpStatus >= 500) {
        return failure("UNVERIFIED", networkId, "UPSTREAM_ERROR", { httpStatus });
      }
      return failure("ERROR", networkId, "HTTP_ERROR", { httpStatus });
    }

    const rawText = await response.text();
    if (typeof rawText !== "string" || rawText.length > MAX_RESPONSE_CHARS) {
      return failure("UNVERIFIED", networkId, "INVALID_RESPONSE_SIZE");
    }

    let payload;
    try {
      payload = JSON.parse(rawText);
    } catch {
      return failure("UNVERIFIED", networkId, "MALFORMED_JSON");
    }

    if (!Array.isArray(payload) || payload.length > O1_ALPHA_MAX_ADDRESSES) {
      return failure("UNVERIFIED", networkId, "INVALID_RESPONSE_SHAPE");
    }

    const seen = new Set();
    const addresses = [];
    for (const value of payload) {
      if (typeof value !== "string" || !ADDRESS_PATTERN.test(value)) {
        return failure("UNVERIFIED", networkId, "INVALID_CONTRACT_ADDRESS");
      }
      const address = value.toLowerCase();
      if (!seen.has(address)) {
        seen.add(address);
        addresses.push(address);
      }
    }

    return {
      status: "SUCCESS",
      networkId,
      addresses,
      count: addresses.length,
      source: "o1_alpha",
      safetyVerdict: "NOT_CHECKED"
    };
  } catch (error) {
    const timedOut = error?.name === "AbortError";
    return failure(
      "UNVERIFIED",
      networkId,
      timedOut ? "REQUEST_TIMEOUT" : "NETWORK_ERROR"
    );
  } finally {
    clearTimeout(timer);
  }
}

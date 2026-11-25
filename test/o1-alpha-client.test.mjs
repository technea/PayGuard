import test from "node:test";
import assert from "node:assert/strict";
import {
  fetchO1AlphaTokenAddresses,
  O1_ALPHA_API_URL
} from "../src/o1-alpha-client.mjs";

const ADDRESS_A = "0x1111111111111111111111111111111111111111";
const ADDRESS_B = "0x2222222222222222222222222222222222222222";

function mockResponse(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: name => headers[name.toLowerCase()] ?? null },
    text: async () => typeof body === "string" ? body : JSON.stringify(body)
  };
}

test("fetches Base Alpha addresses using the documented public GET endpoint", async () => {
  let requestedUrl;
  let requestInit;
  const result = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    {
      fetchImpl: async (url, init) => {
        requestedUrl = url;
        requestInit = init;
        return mockResponse(200, [ADDRESS_A, ADDRESS_B]);
      }
    }
  );

  const parsedUrl = new URL(requestedUrl);
  assert.equal(parsedUrl.origin + parsedUrl.pathname, O1_ALPHA_API_URL);
  assert.equal(parsedUrl.searchParams.get("networkId"), "8453");
  assert.equal(requestInit.method, "GET");
  assert.equal(result.status, "SUCCESS");
  assert.deepEqual(result.addresses, [ADDRESS_A, ADDRESS_B]);
  assert.equal(result.safetyVerdict, "NOT_CHECKED");
});

test("normalizes and deduplicates addresses without changing ranked order", async () => {
  const result = await fetchO1AlphaTokenAddresses(
    { networkId: "8453" },
    {
      fetchImpl: async () => mockResponse(200, [
        ADDRESS_A.toUpperCase().replace("0X", "0x"),
        ADDRESS_B,
        ADDRESS_A
      ])
    }
  );

  assert.equal(result.status, "SUCCESS");
  assert.deepEqual(result.addresses, [ADDRESS_A, ADDRESS_B]);
  assert.equal(result.count, 2);
});

test("rejects missing, invalid, zero, and unsafe network IDs before fetch", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls++;
    throw new Error("fetch must not be called");
  };

  for (const networkId of [undefined, null, 0, -1, 1.5, "0", "abc", Number.MAX_SAFE_INTEGER + 1]) {
    const result = await fetchO1AlphaTokenAddresses({ networkId }, { fetchImpl });
    assert.equal(result.status, "ERROR");
    assert.equal(result.reason, "INVALID_NETWORK_ID");
  }
  assert.equal(calls, 0);
});

test("returns UNVERIFIED for malformed JSON or a non-array response", async () => {
  const malformed = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    { fetchImpl: async () => mockResponse(200, "<html>not json</html>") }
  );
  const wrongShape = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    { fetchImpl: async () => mockResponse(200, { addresses: [ADDRESS_A] }) }
  );

  assert.equal(malformed.reason, "MALFORMED_JSON");
  assert.equal(wrongShape.reason, "INVALID_RESPONSE_SHAPE");
  assert.equal(malformed.status, "UNVERIFIED");
  assert.equal(wrongShape.status, "UNVERIFIED");
});

test("fails closed when an address in the response is malformed", async () => {
  const result = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    { fetchImpl: async () => mockResponse(200, [ADDRESS_A, "0x123"]) }
  );

  assert.equal(result.status, "UNVERIFIED");
  assert.equal(result.reason, "INVALID_CONTRACT_ADDRESS");
  assert.deepEqual(result.addresses, []);
});

test("handles rate limits and preserves Retry-After", async () => {
  const result = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    { fetchImpl: async () => mockResponse(429, {}, { "retry-after": "30" }) }
  );

  assert.equal(result.status, "UNVERIFIED");
  assert.equal(result.reason, "RATE_LIMITED");
  assert.equal(result.retryAfter, "30");
});

test("handles upstream and network failures without returning an empty success", async () => {
  const upstream = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    { fetchImpl: async () => mockResponse(503, {}) }
  );
  const network = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    { fetchImpl: async () => { throw new Error("offline"); } }
  );

  assert.equal(upstream.reason, "UPSTREAM_ERROR");
  assert.equal(network.reason, "NETWORK_ERROR");
  assert.equal(upstream.status, "UNVERIFIED");
  assert.equal(network.status, "UNVERIFIED");
});

test("enforces the documented 1,000-address response maximum", async () => {
  const addresses = Array.from({ length: 1_001 }, (_, index) =>
    "0x" + index.toString(16).padStart(40, "0")
  );
  const result = await fetchO1AlphaTokenAddresses(
    { networkId: 8453 },
    { fetchImpl: async () => mockResponse(200, addresses) }
  );

  assert.equal(result.status, "UNVERIFIED");
  assert.equal(result.reason, "INVALID_RESPONSE_SHAPE");
});

import test from "node:test";
import assert from "node:assert/strict";
import {
  payGuardDiscoverO1AlphaTokens,
  payGuardO1AlphaDiscoveryTool
} from "../src/plugin.mjs";

const ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const UNVERIFIED_ADDRESS = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

function response(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    text: async () => JSON.stringify(body)
  };
}

test("registers the o1 Alpha discovery tool in the plugin surface", () => {
  assert.equal(payGuardO1AlphaDiscoveryTool.name, "payguard_discover_o1_alpha_tokens");
  assert.equal(payGuardO1AlphaDiscoveryTool.inputSchema.properties.networkId.enum[0], 8453);
});

test("rejects non-Base chains and invalid limits before making requests", async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; throw new Error("unexpected request"); };

  const wrongChain = await payGuardDiscoverO1AlphaTokens({ networkId: 56 }, { fetchImpl });
  const wrongLimit = await payGuardDiscoverO1AlphaTokens({ limit: 26 }, { fetchImpl });

  assert.equal(wrongChain.error, "UNSUPPORTED_CHAIN");
  assert.equal(wrongLimit.error, "INVALID_LIMIT");
  assert.equal(calls, 0);
});

test("discovers Alpha contracts and sends each through the existing GoPlus engine", async () => {
  const requested = [];
  const fetchImpl = async url => {
    requested.push(String(url));
    if (String(url).includes("/alpha-tokens")) return response([ADDRESS]);
    return response({
      code: 1,
      message: "OK",
      result: {
        [ADDRESS]: {
          token_name: "Alpha Example",
          token_symbol: "ALPHA",
          is_open_source: "1",
          is_in_dex: "1"
        }
      }
    });
  };

  const result = await payGuardDiscoverO1AlphaTokens({ networkId: 8453, limit: 10 }, { fetchImpl });

  assert.equal(result.status, "SUCCESS");
  assert.equal(result.count, 1);
  assert.equal(result.tokens[0].contractAddress, ADDRESS);
  assert.equal(result.tokens[0].security.verdict, "PASS");
  assert.equal(result.summary.totalScreened, 1);
  assert.equal(requested.length, 2);
  assert.ok(requested.some(url => url.includes("/alpha-tokens")));
  assert.ok(requested.some(url => url.includes("token_security/8453")));
});

test("keeps discovery distinct from safety when screening is disabled", async () => {
  const result = await payGuardDiscoverO1AlphaTokens(
    { screen: false },
    { fetchImpl: async () => response([ADDRESS]) }
  );
  assert.equal(result.status, "SUCCESS");
  assert.equal(result.tokens[0].securityStatus, "NOT_CHECKED");
  assert.equal(result.tokens[0].verdict, "UNVERIFIED");
  assert.equal(result.safetyVerdict, "NOT_CHECKED");
});

test("keeps discovery successful but marks failed GoPlus screening UNVERIFIED", async () => {
  const fetchImpl = async url => {
    if (String(url).includes("/alpha-tokens")) return response([UNVERIFIED_ADDRESS]);
    throw new Error("GoPlus unavailable");
  };

  const result = await payGuardDiscoverO1AlphaTokens({ networkId: 8453 }, { fetchImpl });

  assert.equal(result.status, "SUCCESS");
  assert.equal(result.count, 1);
  assert.equal(result.tokens[0].contractAddress, UNVERIFIED_ADDRESS);
  assert.equal(result.tokens[0].security.verdict, "UNVERIFIED");
  assert.equal(result.summary.unverifiedCount, 1);
  assert.equal(result.summary.passCount, 0);
});

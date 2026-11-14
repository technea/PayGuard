/**
 * PayGuard Alchemy Multi-Page Pagination Mock Test Suite
 *
 * Verifies robust Alchemy token balance pagination, pageKey traversal,
 * deduplication, zero-balance filtering, cycle guards, and error resilience.
 * Does not require a live network connection or real API key.
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  fetchAlchemyTokenBalances,
  scanBaseWalletTokens,
  getWalletPortfolio,
  OFFICIAL_BASE_TOKENS,
  normalizeMaxPages,
  DEFAULT_MAX_PAGES,
  MAX_ALLOWED_PAGES
} from "../src/wallet-token-scanner.mjs";

const TEST_WALLET = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const MOCK_API_KEY = "mock_alchemy_api_key_for_testing";

test("1. Multi-page pagination traverses 3 pages and combines all tokens", async () => {
  const requests = [];

  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requests.push({ id: body.id, method: body.method, params: body.params });

    if (body.params?.[2]?.pageKey === "page_2_key") {
      // Page 2
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            pageKey: "page_3_key",
            tokenBalances: [
              { contractAddress: "0x2222222222222222222222222222222222222222", tokenBalance: "0x200" },
              { contractAddress: "0x3333333333333333333333333333333333333333", tokenBalance: "0x300" }
            ]
          }
        })
      };
    }

    if (body.params?.[2]?.pageKey === "page_3_key") {
      // Page 3 (Final page: no pageKey)
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            pageKey: null,
            tokenBalances: [
              { contractAddress: "0x4444444444444444444444444444444444444444", tokenBalance: "0x400" }
            ]
          }
        })
      };
    }

    // Page 1 (initial call: no pageKey in params)
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          pageKey: "page_2_key",
          tokenBalances: [
            { contractAddress: "0x0000000000000000000000000000000000000001", tokenBalance: "0x100" },
            { contractAddress: "0x1111111111111111111111111111111111111111", tokenBalance: "0x150" }
          ]
        }
      })
    };
  };

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    maxPages: 5
  });

  // Verify request sequence
  assert.equal(requests.length, 3, "Must perform exactly 3 RPC calls");
  assert.deepEqual(requests[0].params, [TEST_WALLET, "erc20"], "Page 1 must not include pageKey");
  assert.equal(requests[1].params[2]?.pageKey, "page_2_key", "Page 2 must pass page_2_key");
  assert.equal(requests[2].params[2]?.pageKey, "page_3_key", "Page 3 must pass page_3_key");

  // Verify combined results
  assert.equal(result.available, true);
  assert.equal(result.pageCount, 3);
  assert.equal(result.totalDiscovered, 5);
  assert.equal(result.items.length, 5);
  assert.equal(result.hasMorePages, false);
  assert.equal(result.nextPageKey, null);

  const addresses = result.items.map(i => i.contractAddress.toLowerCase());
  assert.ok(addresses.includes("0x0000000000000000000000000000000000000001"));
  assert.ok(addresses.includes("0x1111111111111111111111111111111111111111"));
  assert.ok(addresses.includes("0x2222222222222222222222222222222222222222"));
  assert.ok(addresses.includes("0x3333333333333333333333333333333333333333"));
  assert.ok(addresses.includes("0x4444444444444444444444444444444444444444"));
});

test("2. Pagination respects maxPages constraint and signals hasMorePages", async () => {
  let callCount = 0;
  const mockFetch = async (url, options) => {
    callCount++;
    const body = JSON.parse(options.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          pageKey: `next_page_${callCount + 1}`,
          tokenBalances: [
            { contractAddress: `0x${callCount.toString().padStart(40, "0")}`, tokenBalance: "0x10" }
          ]
        }
      })
    };
  };

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    maxPages: 2
  });

  assert.equal(callCount, 2, "Must stop when maxPages limit of 2 is reached");
  assert.equal(result.pageCount, 2);
  assert.equal(result.hasMorePages, true);
  assert.equal(result.nextPageKey, "next_page_3");
  assert.equal(result.items.length, 2);
});

test("3. Prevents infinite loops and reports explicit PARTIAL status with warning on repeated pageKey", async () => {
  let callCount = 0;
  const mockFetch = async (url, options) => {
    callCount++;
    const body = JSON.parse(options.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          pageKey: "stuck_cyclic_key",
          tokenBalances: [
            { contractAddress: `0x${callCount.toString().padStart(40, "0")}`, tokenBalance: "0x10" }
          ]
        }
      })
    };
  };

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    maxPages: 10
  });

  // Call 1 returns pageKey: "stuck_cyclic_key".
  // Call 2 requests with pageKey: "stuck_cyclic_key", and response gives "stuck_cyclic_key" again.
  // Next iteration detects "stuck_cyclic_key" already in seenPageKeys and breaks cycle cleanly.
  assert.equal(callCount, 2, "Must break cycle after querying duplicate pageKey once");
  assert.equal(result.pageCount, 2);
  assert.equal(result.hasMorePages, false, "Cycle terminated so hasMorePages must be false");
  assert.equal(result.cycleDetected, true, "Must flag cycleDetected as true");
  assert.equal(result.partial, true, "Must flag partial as true");
  assert.equal(result.status, "PARTIAL", "Must explicitly report PARTIAL status");
  assert.ok(typeof result.warning === "string" && result.warning.includes("Pagination cycle detected"));
  assert.equal(result.items.length, 2, "Already discovered tokens must be preserved");
});

test("4. Empty string or whitespace pageKey cleanly terminates pagination", async () => {
  let callCount = 0;
  const mockFetch = async (url, options) => {
    callCount++;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: 1,
        result: {
          pageKey: "   ",
          tokenBalances: [
            { contractAddress: "0x1111111111111111111111111111111111111111", tokenBalance: "0x20" }
          ]
        }
      })
    };
  };

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    maxPages: 5
  });

  assert.equal(callCount, 1, "Must terminate after 1 page when pageKey is whitespace");
  assert.equal(result.pageCount, 1);
  assert.equal(result.hasMorePages, false);
});

test("5. Deduplicates tokens appearing across multiple pages", async () => {
  const duplicateToken = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (!body.params?.[2]?.pageKey) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: 1,
          result: {
            pageKey: "page_2",
            tokenBalances: [
              { contractAddress: duplicateToken, tokenBalance: "0x1000" },
              { contractAddress: "0x0000000000000000000000000000000000000001", tokenBalance: "0x2000" }
            ]
          }
        })
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: 2,
        result: {
          pageKey: null,
          tokenBalances: [
            { contractAddress: duplicateToken, tokenBalance: "0x1000" }, // duplicate across pages
            { contractAddress: "0x2222222222222222222222222222222222222222", tokenBalance: "0x3000" }
          ]
        }
      })
    };
  };

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    maxPages: 3
  });

  assert.equal(result.items.length, 3, "Duplicate token must be deduplicated across pages");
  const usdcItems = result.items.filter(i => i.contractAddress.toLowerCase() === duplicateToken.toLowerCase());
  assert.equal(usdcItems.length, 1);
});

test("6. Zero-balance tokens are filtered out across all pages", async () => {
  const mockFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      jsonrpc: "2.0",
      id: 1,
      result: {
        pageKey: null,
        tokenBalances: [
          { contractAddress: "0x1111111111111111111111111111111111111111", tokenBalance: "0x0" },
          { contractAddress: "0x2222222222222222222222222222222222222222", tokenBalance: "0x00" },
          { contractAddress: "0x3333333333333333333333333333333333333333", tokenBalance: null },
          { contractAddress: "0x4444444444444444444444444444444444444444", tokenBalance: "0x500" }
        ]
      }
    })
  });

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY
  });

  assert.equal(result.items.length, 1, "Only non-zero balance tokens should be returned");
  assert.equal(result.items[0].contractAddress.toLowerCase(), "0x4444444444444444444444444444444444444444");
});

test("7. Mid-pagination network/HTTP failure preserves partial discoveries", async () => {
  let callCount = 0;
  const mockFetch = async () => {
    callCount++;
    if (callCount === 1) {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: 1,
          result: {
            pageKey: "page_2_key",
            tokenBalances: [
              { contractAddress: "0x1111111111111111111111111111111111111111", tokenBalance: "0x100" }
            ]
          }
        })
      };
    }
    return {
      ok: false,
      status: 429,
      json: async () => ({ error: { message: "Rate limit exceeded" } })
    };
  };

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    maxPages: 3
  });

  assert.equal(result.available, true, "Available must be true since page 1 had discoveries");
  assert.equal(result.partial, true, "Partial flag must be set on mid-pagination error");
  assert.equal(result.items.length, 1);
  assert.ok(result.error.includes("429"));
  assert.equal(result.pageCount, 2);
  assert.equal(result.nextPageKey, "page_2_key");
});

test("8. Starting from an initial pageKey queries from that page", async () => {
  let requestedKey = null;
  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    requestedKey = body.params?.[2]?.pageKey;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: 1,
        result: {
          pageKey: null,
          tokenBalances: [
            { contractAddress: "0x1111111111111111111111111111111111111111", tokenBalance: "0x50" }
          ]
        }
      })
    };
  };

  const result = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    pageKey: "resume_cursor_abc",
    maxPages: 1
  });

  assert.equal(requestedKey, "resume_cursor_abc", "First request must pass the initial pageKey");
  assert.equal(result.items.length, 1);
});

test("9. maxCount option is correctly propagated to RPC params", async () => {
  let passedMaxCount = null;
  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    passedMaxCount = body.params?.[2]?.maxCount;
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: 1,
        result: {
          pageKey: null,
          tokenBalances: []
        }
      })
    };
  };

  await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetch,
    alchemyApiKey: MOCK_API_KEY,
    maxCount: 25
  });

  assert.equal(passedMaxCount, 25, "maxCount must be passed into Alchemy RPC options");
});

test("10. scanBaseWalletTokens flags PARTIAL and reports warning when pagination cycle occurs", async () => {
  let alchemyCallCount = 0;
  const mockFetch = async (url, options) => {
    const urlStr = String(url);
    if (urlStr.includes("alchemy.com")) {
      alchemyCallCount++;
      const body = JSON.parse(options.body);
      if (body.method === "eth_getBalance") {
        return {
          ok: true,
          status: 200,
          json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x1bc16d674ec80000" }) // 2 ETH
        };
      }
      if (body.method === "alchemy_getTokenBalances") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              pageKey: "loop_key_x",
              tokenBalances: [
                { contractAddress: "0x1111111111111111111111111111111111111111", tokenBalance: "0x100" }
              ]
            }
          })
        };
      }
    }
    if (urlStr.includes("gopluslabs.io")) {
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ code: 1, result: {} }),
        json: async () => ({})
      };
    }
    if (urlStr.includes("mainnet.base.org")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: 1, result: "0x0" })
      };
    }
    throw new Error(`Unexpected mock URL: ${url}`);
  };

  const scan = await scanBaseWalletTokens(
    { walletAddress: TEST_WALLET },
    { fetchImpl: mockFetch, alchemyApiKey: MOCK_API_KEY }
  );

  assert.equal(scan.status, "SUCCESS");
  assert.equal(scan.scanCompletionStatus, "PARTIAL", "Cycle must result in PARTIAL scanCompletionStatus");
  assert.ok(typeof scan.paginationWarning === "string", "Must expose paginationWarning string");
  assert.ok(scan.paginationWarning.includes("Pagination cycle detected"));
  assert.ok(scan.tokens.length > 0, "Discovered tokens must be preserved");
});

test("11. Official Base Token Registry is merged with Alchemy discoveries without duplicate contract addresses", async () => {
  const USDC_ADDRESS = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
  const CUSTOM_TOKEN = "0x9999999999999999999999999999999999999999";

  const mockFetch = async (url, options) => {
    const urlStr = String(url);
    if (urlStr.includes("alchemy.com")) {
      const body = JSON.parse(options.body);
      if (body.method === "eth_getBalance") {
        return {
          ok: true,
          status: 200,
          json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0xde0b6b3a7640000" }) // 1 ETH
        };
      }
      if (body.method === "alchemy_getTokenBalances") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              pageKey: null,
              tokenBalances: [
                { contractAddress: USDC_ADDRESS, tokenBalance: "0x5f5e100" }, // 100 USDC discovered via Alchemy
                { contractAddress: CUSTOM_TOKEN, tokenBalance: "0x1000" }     // Custom token
              ]
            }
          })
        };
      }
    }
    if (urlStr.includes("gopluslabs.io")) {
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ code: 1, result: {} }),
        json: async () => ({})
      };
    }
    if (urlStr.includes("mainnet.base.org")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: 1, result: "0x0" })
      };
    }
    throw new Error(`Unexpected mock URL: ${url}`);
  };

  const scan = await scanBaseWalletTokens(
    { walletAddress: TEST_WALLET },
    { fetchImpl: mockFetch, alchemyApiKey: MOCK_API_KEY }
  );

  assert.equal(scan.status, "SUCCESS");
  assert.equal(scan.scanCompletionStatus, "COMPLETE");

  const scannedAddresses = scan.tokens.map(t => t.contractAddress.toLowerCase());

  // 1. Verify all official registry tokens are present
  for (const officialAddr of Object.keys(OFFICIAL_BASE_TOKENS)) {
    assert.ok(
      scannedAddresses.includes(officialAddr.toLowerCase()),
      `Official token ${officialAddr} must be included in scan results`
    );
  }

  // 2. Verify custom token is present
  assert.ok(scannedAddresses.includes(CUSTOM_TOKEN.toLowerCase()), "Alchemy-discovered custom token must be included");

  // 3. Verify NO duplicate contract addresses
  const uniqueAddresses = new Set(scannedAddresses);
  assert.equal(
    uniqueAddresses.size,
    scannedAddresses.length,
    "All scanned token contract addresses must be unique (no duplicates)"
  );

  // 4. Verify Alchemy-discovered balance is preserved for USDC (not overwritten with null/0)
  const usdcToken = scan.tokens.find(t => t.contractAddress.toLowerCase() === USDC_ADDRESS);
  assert.ok(usdcToken, "USDC must be present");
  assert.equal(usdcToken.balance, "0x5f5e100", "USDC must preserve Alchemy-discovered balance");
  assert.equal(usdcToken.isVerifiedOfficial, true, "USDC must still be verified official");
});

test("12. getWalletPortfolio multi-page traversal combines assets across pages with sensible default (maxPages: 5)", async () => {
  const tokenA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const tokenB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === "eth_getBalance") {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x1bc16d674ec80000" }) // 2 ETH
      };
    }
    if (body.method === "alchemy_getTokenBalances") {
      if (body.params?.[2]?.pageKey === "portfolio_page_2") {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              pageKey: null,
              tokenBalances: [
                { contractAddress: tokenB, tokenBalance: "0x200" }
              ]
            }
          })
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            pageKey: "portfolio_page_2",
            tokenBalances: [
              { contractAddress: tokenA, tokenBalance: "0x100" }
            ]
          }
        })
      };
    }
    if (body.method === "alchemy_getTokenMetadata") {
      const addr = body.params?.[0]?.toLowerCase();
      if (addr === tokenA) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            jsonrpc: "2.0",
            id: body.id,
            result: { name: "Token A", symbol: "TKNA", decimals: 18, logo: "https://example.com/a.png" }
          })
        };
      }
      if (addr === tokenB) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            jsonrpc: "2.0",
            id: body.id,
            result: { name: "Token B", symbol: "TKNB", decimals: 6, logo: "https://example.com/b.png" }
          })
        };
      }
    }
    throw new Error(`Unexpected method or params: ${JSON.stringify(body)}`);
  };

  // Called without explicit maxPages: must use sensible default (5 pages) and traverse all available pages
  const portfolio = await getWalletPortfolio(
    { walletAddress: TEST_WALLET },
    { fetchImpl: mockFetch, alchemyApiKey: MOCK_API_KEY }
  );

  assert.equal(portfolio.status, "SUCCESS");
  assert.equal(portfolio.scanCompletionStatus, "COMPLETE");
  assert.equal(portfolio.hasMorePages, false);
  assert.equal(portfolio.nextPageKey, null);
  assert.equal(portfolio.tokenHoldingsCount, 2);
  assert.equal(portfolio.tokens.length, 2);

  const foundA = portfolio.tokens.find(t => t.contractAddress.toLowerCase() === tokenA);
  const foundB = portfolio.tokens.find(t => t.contractAddress.toLowerCase() === tokenB);
  assert.ok(foundA, "Token A from page 1 must be present");
  assert.equal(foundA.symbol, "TKNA");
  assert.equal(foundA.balanceRaw, "0x100");

  assert.ok(foundB, "Token B from page 2 must be present");
  assert.equal(foundB.symbol, "TKNB");
  assert.equal(foundB.balanceRaw, "0x200");
});

test("13. getWalletPortfolio propagates PARTIAL status, hasMorePages, and nextPageKey when maxPages limit is reached", async () => {
  const tokenA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === "eth_getBalance") {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x1bc16d674ec80000" })
      };
    }
    if (body.method === "alchemy_getTokenBalances") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            pageKey: "page_2_cursor",
            tokenBalances: [
              { contractAddress: tokenA, tokenBalance: "0x100" }
            ]
          }
        })
      };
    }
    if (body.method === "alchemy_getTokenMetadata") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: { name: "Token A", symbol: "TKNA", decimals: 18, logo: null }
        })
      };
    }
    throw new Error(`Unexpected call: ${JSON.stringify(body)}`);
  };

  const portfolio = await getWalletPortfolio(
    { walletAddress: TEST_WALLET },
    { fetchImpl: mockFetch, alchemyApiKey: MOCK_API_KEY, maxPages: 1 }
  );

  assert.equal(portfolio.status, "SUCCESS");
  assert.equal(portfolio.scanCompletionStatus, "PARTIAL", "Exhausting maxPages with pending pageKey must mark scan PARTIAL");
  assert.equal(portfolio.hasMorePages, true);
  assert.equal(portfolio.nextPageKey, "page_2_cursor");
  assert.equal(portfolio.tokenHoldingsCount, 1);
  assert.equal(portfolio.tokens.length, 1);
});

test("14. getWalletPortfolio propagates PARTIAL status and pagination warning when a cycle occurs", async () => {
  let callCount = 0;
  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === "eth_getBalance") {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x1bc16d674ec80000" })
      };
    }
    if (body.method === "alchemy_getTokenBalances") {
      callCount++;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            pageKey: "stuck_portfolio_key",
            tokenBalances: [
              { contractAddress: `0x${callCount.toString().padStart(40, "1")}`, tokenBalance: "0x50" }
            ]
          }
        })
      };
    }
    if (body.method === "alchemy_getTokenMetadata") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: { name: "Test Token", symbol: "TEST", decimals: 18, logo: null }
        })
      };
    }
    throw new Error(`Unexpected call: ${JSON.stringify(body)}`);
  };

  const portfolio = await getWalletPortfolio(
    { walletAddress: TEST_WALLET },
    { fetchImpl: mockFetch, alchemyApiKey: MOCK_API_KEY, maxPages: 5 }
  );

  assert.equal(portfolio.status, "SUCCESS");
  assert.equal(portfolio.scanCompletionStatus, "PARTIAL");
  assert.equal(portfolio.hasMorePages, false);
  assert.ok(typeof portfolio.paginationWarning === "string");
  assert.ok(portfolio.paginationWarning.includes("Pagination cycle detected"));
  assert.equal(portfolio.tokens.length, 2, "Discovered tokens prior to cycle break must be preserved");
});

test("15. normalizeMaxPages safely bounds Infinity, excessively large numbers, NaN, negatives, and invalid values", () => {
  // Safe upper bound clamping
  assert.equal(normalizeMaxPages(Infinity), MAX_ALLOWED_PAGES, "Infinity must clamp to MAX_ALLOWED_PAGES");
  assert.equal(normalizeMaxPages("+Infinity"), MAX_ALLOWED_PAGES, "'+Infinity' string must clamp to MAX_ALLOWED_PAGES");
  assert.equal(normalizeMaxPages("Infinity"), MAX_ALLOWED_PAGES, "'Infinity' string must clamp to MAX_ALLOWED_PAGES");
  assert.equal(normalizeMaxPages(1000), MAX_ALLOWED_PAGES, "1000 must clamp to MAX_ALLOWED_PAGES");
  assert.equal(normalizeMaxPages("999999"), MAX_ALLOWED_PAGES, "'999999' string must clamp to MAX_ALLOWED_PAGES");

  // Fallback on invalid, NaN, negative, zero, or non-numeric
  assert.equal(normalizeMaxPages(NaN), DEFAULT_MAX_PAGES, "NaN must fall back to DEFAULT_MAX_PAGES");
  assert.equal(normalizeMaxPages(-10), DEFAULT_MAX_PAGES, "-10 must fall back to DEFAULT_MAX_PAGES");
  assert.equal(normalizeMaxPages(0), DEFAULT_MAX_PAGES, "0 must fall back to DEFAULT_MAX_PAGES");
  assert.equal(normalizeMaxPages(-Infinity), DEFAULT_MAX_PAGES, "-Infinity must fall back to DEFAULT_MAX_PAGES");
  assert.equal(normalizeMaxPages("invalid"), DEFAULT_MAX_PAGES, "'invalid' must fall back to DEFAULT_MAX_PAGES");
  assert.equal(normalizeMaxPages("   "), DEFAULT_MAX_PAGES, "Whitespace must fall back to DEFAULT_MAX_PAGES");
  assert.equal(normalizeMaxPages(null), DEFAULT_MAX_PAGES, "null must fall back to DEFAULT_MAX_PAGES");
  assert.equal(normalizeMaxPages(undefined), DEFAULT_MAX_PAGES, "undefined must fall back to DEFAULT_MAX_PAGES");

  // Custom fallback propagation
  assert.equal(normalizeMaxPages("invalid", 10), 10, "Custom fallback must be respected on invalid input");

  // Valid inputs preserved and sanitized
  assert.equal(normalizeMaxPages(1), 1);
  assert.equal(normalizeMaxPages(3), 3);
  assert.equal(normalizeMaxPages("7"), 7);
  assert.equal(normalizeMaxPages(4.9), 4, "Floating numbers must be truncated to integer");
});

test("16. fetchAlchemyTokenBalances safely bounds Infinity without unbounded execution", async () => {
  let infiniteLoopCallCount = 0;
  const mockFetchInfinite = async (url, options) => {
    infiniteLoopCallCount++;
    const body = JSON.parse(options.body);
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          pageKey: `next_cursor_${infiniteLoopCallCount}`,
          tokenBalances: [
            { contractAddress: `0x${infiniteLoopCallCount.toString().padStart(40, "0")}`, tokenBalance: "0x10" }
          ]
        }
      })
    };
  };

  // Caller attempts unbounded crawl with maxPages: Infinity
  const boundedResult = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: mockFetchInfinite,
    alchemyApiKey: MOCK_API_KEY,
    maxPages: Infinity
  });

  assert.equal(
    infiniteLoopCallCount,
    MAX_ALLOWED_PAGES,
    `Must terminate cleanly at MAX_ALLOWED_PAGES (${MAX_ALLOWED_PAGES}) without unbounded execution`
  );
  assert.equal(boundedResult.pageCount, MAX_ALLOWED_PAGES);
  assert.equal(boundedResult.hasMorePages, true);
  assert.equal(boundedResult.nextPageKey, `next_cursor_${MAX_ALLOWED_PAGES}`);
  assert.equal(boundedResult.items.length, MAX_ALLOWED_PAGES);

  // Negative / NaN maxPages falls back to safe default
  const defaultFallbackResult = await fetchAlchemyTokenBalances(TEST_WALLET, {
    fetchImpl: async (url, options) => {
      const body = JSON.parse(options.body);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            pageKey: null,
            tokenBalances: [
              { contractAddress: "0x1111111111111111111111111111111111111111", tokenBalance: "0x50" }
            ]
          }
        })
      };
    },
    alchemyApiKey: MOCK_API_KEY,
    maxPages: -999
  });
  assert.equal(defaultFallbackResult.pageCount, 1);
  assert.equal(defaultFallbackResult.hasMorePages, false);
});

test("17. getWalletPortfolio marks scanCompletionStatus as PARTIAL and exposes warning on initial Alchemy HTTP 503 failure", async () => {
  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === "eth_getBalance") {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x1bc16d674ec80000" }) // 2 ETH
      };
    }
    if (body.method === "alchemy_getTokenBalances") {
      return {
        ok: false,
        status: 503,
        json: async () => ({ error: { message: "Service Unavailable" } })
      };
    }
    if (body.method === "eth_call") {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x0" })
      };
    }
    throw new Error(`Unexpected mock request: ${JSON.stringify(body)}`);
  };

  const portfolio = await getWalletPortfolio(
    { walletAddress: TEST_WALLET },
    { fetchImpl: mockFetch, alchemyApiKey: MOCK_API_KEY }
  );

  assert.equal(portfolio.status, "SUCCESS");
  // CRITICAL: Must not report COMPLETE on initial Alchemy API failure
  assert.equal(
    portfolio.scanCompletionStatus,
    "PARTIAL",
    "Must explicitly report PARTIAL status when initial Alchemy request fails"
  );
  assert.equal(portfolio.hasMorePages, false);
  assert.ok(portfolio.paginationWarning, "Must expose paginationWarning");
  assert.ok(
    portfolio.paginationWarning.includes("503") || portfolio.paginationWarning.includes("unavailable"),
    "Warning must indicate Alchemy failure"
  );
  assert.ok(portfolio.warning, "Must expose warning property");
  // Official Base registry fallback preserved
  assert.ok(portfolio.tokenHoldingsCount > 0, "Canonical Base registry fallback must be executed");
  assert.ok(portfolio.tokens.length > 0);
});

test("18. getWalletPortfolio safely bounds maxPages: Infinity to MAX_ALLOWED_PAGES (50) and reports PARTIAL with hasMorePages", async () => {
  let alchemyTokenBalancesCallCount = 0;

  const mockFetch = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === "eth_getBalance") {
      return {
        ok: true,
        status: 200,
        json: async () => ({ jsonrpc: "2.0", id: body.id, result: "0x1bc16d674ec80000" })
      };
    }
    if (body.method === "alchemy_getTokenBalances") {
      alchemyTokenBalancesCallCount++;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            pageKey: `portfolio_cursor_${alchemyTokenBalancesCallCount}`,
            tokenBalances: [
              { contractAddress: `0x${alchemyTokenBalancesCallCount.toString().padStart(40, "0")}`, tokenBalance: "0x10" }
            ]
          }
        })
      };
    }
    if (body.method === "alchemy_getTokenMetadata") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          jsonrpc: "2.0",
          id: body.id,
          result: { name: "Mock Token", symbol: "MCK", decimals: 18, logo: null }
        })
      };
    }
    throw new Error(`Unexpected mock request: ${JSON.stringify(body)}`);
  };

  const portfolio = await getWalletPortfolio(
    { walletAddress: TEST_WALLET },
    { fetchImpl: mockFetch, alchemyApiKey: MOCK_API_KEY, maxPages: Infinity }
  );

  assert.equal(
    alchemyTokenBalancesCallCount,
    MAX_ALLOWED_PAGES,
    `Must execute exactly MAX_ALLOWED_PAGES (${MAX_ALLOWED_PAGES}) requests without infinite loop`
  );
  assert.equal(portfolio.status, "SUCCESS");
  assert.equal(
    portfolio.scanCompletionStatus,
    "PARTIAL",
    "Scan must be PARTIAL since more pages remain"
  );
  assert.equal(portfolio.hasMorePages, true, "hasMorePages must be true when bounded by MAX_ALLOWED_PAGES");
  assert.equal(portfolio.nextPageKey, `portfolio_cursor_${MAX_ALLOWED_PAGES}`);
  assert.equal(portfolio.tokenHoldingsCount, MAX_ALLOWED_PAGES);
  assert.equal(portfolio.tokens.length, MAX_ALLOWED_PAGES);
});


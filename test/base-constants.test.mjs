import test from "node:test";
import assert from "node:assert/strict";
import {
  BASE_MAINNET_CHAIN_ID,
  BASE_MAINNET_CHAIN_ID_HEX,
  BASE_MAINNET_RPC_URL,
  BASE_MAINNET_EXPLORER_URL,
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_CHAIN_ID_HEX,
  BASE_SEPOLIA_RPC_URL,
  BASE_SEPOLIA_EXPLORER_URL,
  BASE_NETWORKS,
  isBaseNetwork
} from "../src/core/base-constants.mjs";

test("1. Base Mainnet constants match official protocol specs", () => {
  assert.equal(BASE_MAINNET_CHAIN_ID, 8453);
  assert.equal(BASE_MAINNET_CHAIN_ID_HEX, "0x2105");
  assert.equal(BASE_MAINNET_RPC_URL, "https://mainnet.base.org");
  assert.equal(BASE_MAINNET_EXPLORER_URL, "https://basescan.org");

  const mainnet = BASE_NETWORKS[BASE_MAINNET_CHAIN_ID];
  assert.ok(mainnet);
  assert.equal(mainnet.name, "Base Mainnet");
  assert.equal(mainnet.isTestnet, false);
  assert.equal(mainnet.nativeCurrency.symbol, "ETH");
  assert.equal(mainnet.nativeCurrency.decimals, 18);
});

test("2. Base Sepolia constants match official protocol specs", () => {
  assert.equal(BASE_SEPOLIA_CHAIN_ID, 84532);
  assert.equal(BASE_SEPOLIA_CHAIN_ID_HEX, "0x14a34");
  assert.equal(BASE_SEPOLIA_RPC_URL, "https://sepolia.base.org");
  assert.equal(BASE_SEPOLIA_EXPLORER_URL, "https://sepolia.basescan.org");

  const sepolia = BASE_NETWORKS[BASE_SEPOLIA_CHAIN_ID];
  assert.ok(sepolia);
  assert.equal(sepolia.name, "Base Sepolia");
  assert.equal(sepolia.isTestnet, true);
  assert.equal(sepolia.nativeCurrency.symbol, "ETH");
});

test("3. isBaseNetwork identifies decimal, hex, and string chain IDs correctly", () => {
  assert.equal(isBaseNetwork(8453), true);
  assert.equal(isBaseNetwork("8453"), true);
  assert.equal(isBaseNetwork("0x2105"), true);
  assert.equal(isBaseNetwork("0X2105"), true);

  assert.equal(isBaseNetwork(84532), true);
  assert.equal(isBaseNetwork("84532"), true);
  assert.equal(isBaseNetwork("0x14a34"), true);

  // Non-Base networks fail closed
  assert.equal(isBaseNetwork(1), false); // Ethereum Mainnet
  assert.equal(isBaseNetwork("1"), false);
  assert.equal(isBaseNetwork("0x1"), false);
  assert.equal(isBaseNetwork(137), false); // Polygon
  assert.equal(isBaseNetwork(null), false);
  assert.equal(isBaseNetwork(undefined), false);
  assert.equal(isBaseNetwork(""), false);
  assert.equal(isBaseNetwork("invalid"), false);
});


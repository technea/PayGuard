/**
 * PayGuard Base Network Constants
 *
 * Authoritative constants for Base L2 networks (Mainnet and Sepolia).
 * Sourced directly from official Base protocol specifications:
 * - Base Mainnet Chain ID: 8453 (0x2105)
 * - Base Sepolia Chain ID: 84532 (0x14a34)
 * - Canonical RPCs: https://mainnet.base.org, https://sepolia.base.org
 * - Explorers: https://basescan.org, https://sepolia.basescan.org
 *
 * Architectural Boundary:
 * Pure, frozen configuration constants. Contains zero dependencies,
 * zero side effects, and executes zero network requests.
 */

export const BASE_MAINNET_CHAIN_ID = 8453;
export const BASE_MAINNET_CHAIN_ID_HEX = "0x2105";
export const BASE_MAINNET_RPC_URL = "https://mainnet.base.org";
export const BASE_MAINNET_EXPLORER_URL = "https://basescan.org";

export const BASE_SEPOLIA_CHAIN_ID = 84532;
export const BASE_SEPOLIA_CHAIN_ID_HEX = "0x14a34";
export const BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org";
export const BASE_SEPOLIA_EXPLORER_URL = "https://sepolia.basescan.org";

export const BASE_NETWORKS = Object.freeze({
  [BASE_MAINNET_CHAIN_ID]: Object.freeze({
    chainId: BASE_MAINNET_CHAIN_ID,
    chainIdHex: BASE_MAINNET_CHAIN_ID_HEX,
    name: "Base Mainnet",
    rpcUrl: BASE_MAINNET_RPC_URL,
    explorerUrl: BASE_MAINNET_EXPLORER_URL,
    nativeCurrency: Object.freeze({
      name: "Ether",
      symbol: "ETH",
      decimals: 18
    }),
    isTestnet: false
  }),
  [BASE_SEPOLIA_CHAIN_ID]: Object.freeze({
    chainId: BASE_SEPOLIA_CHAIN_ID,
    chainIdHex: BASE_SEPOLIA_CHAIN_ID_HEX,
    name: "Base Sepolia",
    rpcUrl: BASE_SEPOLIA_RPC_URL,
    explorerUrl: BASE_SEPOLIA_EXPLORER_URL,
    nativeCurrency: Object.freeze({
      name: "Sepolia Ether",
      symbol: "ETH",
      decimals: 18
    }),
    isTestnet: true
  })
});

/**
 * Returns true if the given chainId (number, decimal string, or hex string) is a supported Base network.
 * @param {string|number} chainId
 * @returns {boolean}
 */
export function isBaseNetwork(chainId) {
  if (chainId === null || chainId === undefined) return false;
  let parsed = null;
  if (typeof chainId === "number") {
    parsed = chainId;
  } else if (typeof chainId === "string") {
    const trimmed = chainId.trim();
    if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
      parsed = parseInt(trimmed, 16);
    } else {
      parsed = parseInt(trimmed, 10);
    }
  }
  return parsed === BASE_MAINNET_CHAIN_ID || parsed === BASE_SEPOLIA_CHAIN_ID;
}

export default {
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
};


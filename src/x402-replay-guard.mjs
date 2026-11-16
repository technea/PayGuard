/**
 * Process-local replay guard for x402 exact EVM / EIP-3009 authorizations.
 *
 * The token contract remains the authoritative replay boundary: EIP-3009 consumes
 * (authorizer, nonce) on-chain. This guard adds same-process protection against
 * concurrent/repeated facilitator submissions. Use a durable, atomic adapter for
 * multi-instance deployments.
 */
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const NONCE_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;
const UINT_PATTERN = /^(0|[1-9][0-9]*)$/;
const MAX_UINT256 = (1n << 256n) - 1n;

export function validateEip3009Authorization(paymentPayload, requirements) {
  if (paymentPayload?.x402Version !== 2) {
    return { valid: false, reason: "Live x402 settlement requires x402Version 2." };
  }
  const accepted = paymentPayload.accepted;
  const payload = paymentPayload.payload;
  const authorization = payload?.authorization;
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization)) {
    return { valid: false, reason: "Live exact EVM payment requires payload.authorization (EIP-3009)." };
  }
  if (accepted?.extra?.assetTransferMethod && accepted.extra.assetTransferMethod !== "eip3009") {
    return { valid: false, reason: "PayGuard currently supports the x402 exact EVM eip3009 transfer method only." };
  }
  if (typeof authorization.from !== "string" || !ADDRESS_PATTERN.test(authorization.from)) {
    return { valid: false, reason: "EIP-3009 authorization.from must be a valid EVM address." };
  }
  if (typeof authorization.to !== "string" || !ADDRESS_PATTERN.test(authorization.to)) {
    return { valid: false, reason: "EIP-3009 authorization.to must be a valid EVM address." };
  }
  if (authorization.to.toLowerCase() !== requirements.payTo.toLowerCase()) {
    return { valid: false, reason: "EIP-3009 authorization recipient does not match the required payTo address." };
  }
  for (const field of ["value", "validAfter", "validBefore"]) {
    const value = authorization[field];
    if (typeof value !== "string" || !UINT_PATTERN.test(value)) {
      return { valid: false, reason: "EIP-3009 authorization." + field + " must be an unsigned integer string." };
    }
    if (BigInt(value) > MAX_UINT256) {
      return { valid: false, reason: "EIP-3009 authorization." + field + " exceeds uint256." };
    }
  }
  if (authorization.value !== requirements.amount) {
    return { valid: false, reason: "EIP-3009 authorization.value must exactly match the required payment amount." };
  }
  if (BigInt(authorization.validBefore) <= BigInt(authorization.validAfter)) {
    return { valid: false, reason: "EIP-3009 authorization validity window is invalid." };
  }
  if (typeof authorization.nonce !== "string" || !NONCE_PATTERN.test(authorization.nonce)) {
    return { valid: false, reason: "EIP-3009 authorization.nonce must be a 32-byte hex value." };
  }
  if (typeof payload.signature !== "string" || !SIGNATURE_PATTERN.test(payload.signature)) {
    return { valid: false, reason: "EIP-3009 payload.signature must be a 65-byte hex signature." };
  }
  const key = [
    requirements.network.toLowerCase(),
    requirements.asset.toLowerCase(),
    authorization.from.toLowerCase(),
    authorization.nonce.toLowerCase()
  ].join(":");
  return { valid: true, key };
}

/**
 * Atomic only within this JavaScript process. No TTL/eviction is used because
 * deleting a settled key could re-open a replay window. Capacity exhaustion fails closed.
 */
export function createInMemoryX402ReplayGuard({ maxEntries = 10000 } = {}) {
  if (!Number.isInteger(maxEntries) || maxEntries < 1) {
    throw new TypeError("maxEntries must be a positive integer.");
  }
  const entries = new Map();
  return Object.freeze({
    async claim(key) {
      if (entries.has(key)) return { claimed: false, status: entries.get(key).status };
      if (entries.size >= maxEntries) return { claimed: false, status: "capacity" };
      entries.set(key, { status: "pending" });
      return { claimed: true, status: "pending" };
    },
    async markSettled(key) {
      if (!entries.has(key)) throw new Error("Cannot mark an unreserved x402 authorization as settled.");
      entries.set(key, { status: "settled" });
    },
    async release(key) {
      if (entries.get(key)?.status === "pending") entries.delete(key);
    },
    async getStatus(key) {
      return entries.get(key)?.status ?? null;
    },
    size() {
      return entries.size;
    }
  });
}

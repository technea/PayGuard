/**
 * PayGuard PayBox & x402 Marketplace Integration
 *
 * Implements:
 * 1. x402 HTTP 402 Payment Required flow for PayGuard security scanning
 * 2. Bazaar discovery metadata for autonomous AI agent discovery
 * 3. Verified testnet flow (Sepolia/Base-Sepolia) support
 * 4. PayBox Marketplace tool descriptor and handler
 */

import { plugin } from "./src/plugin.mjs";
import { createInMemoryX402ReplayGuard, validateEip3009Authorization } from "./src/x402-replay-guard.mjs";

export const X402_CONFIG = {
  version: "1.0",
  serviceName: "payguard",
  description: "Security-focused x402 service for AI agents: URL Sentinel phishing detection & Payment Guard intent verification.",
  defaultPriceAtomic: "1000", // e.g. 0.001 USDC (6 decimals)
  network: process.env.PAYGUARD_NETWORK || "eip155:84532", // Base Sepolia testnet
  asset: process.env.PAYGUARD_ASSET || "0x036CbD53842c5426634e7929541eC2318f3dCF7e", // Testnet USDC
  payTo: process.env.PAYGUARD_PAY_TO || "0x20556F0cfA3f93F0206faeb5452d2745e1423469", // Public test receiving address
  facilitatorUrl: process.env.X402_FACILITATOR_URL || "https://facilitator.x402.org"
};

/**
 * Standard Bazaar discovery metadata conforming to x402 Bazaar specifications.
 */
export const BAZAAR_DISCOVERY_METADATA = {
  info: {
    name: "PayGuard Security Service",
    version: "0.1.0",
    description: "Proactive security sentinel and x402 payment intent validation for AI agents and marketplace bots.",
    category: "security",
    tags: ["security", "x402", "url-sentinel", "phishing-detection", "payment-guard", "paybox"],
    author: "PayGuard Core Team",
    endpoints: [
      {
        path: "/api/analyze-url",
        method: "POST",
        description: "Analyze URL for phishing, homoglyphs, and known threat intelligence.",
        input: {
          type: "http",
          body: {
            type: "object",
            required: ["url"],
            properties: {
              url: { type: "string", description: "Target URL to inspect" },
              expectedDomain: { type: "string", description: "Optional trusted domain" },
              checkReputation: { type: "boolean", description: "Enable external threat intelligence check" }
            }
          }
        }
      },
      {
        path: "/api/check-payment",
        method: "POST",
        description: "Verify x402 payment requirements against caller-defined payment policy.",
        input: {
          type: "http",
          body: {
            type: "object",
            required: ["intent", "paymentRequirements"],
            properties: {
              intent: { type: "object", description: "Trusted user payment policy" },
              paymentRequirements: { type: "object", description: "Offered x402 payment requirements" }
            }
          }
        }
      }
    ]
  },
  schema: {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    title: "PayGuardBazaarMetadata",
    type: "object",
    required: ["info"],
    properties: {
      info: { type: "object" }
    }
  }
};

/**
 * Generates an x402 HTTP 402 challenge response for unpaid requests.
 */
export function build402Challenge(resource, priceAtomic = X402_CONFIG.defaultPriceAtomic) {
  return {
    status: 402,
    headers: {
      "www-authenticate": `x402 scheme="exact" network="${X402_CONFIG.network}" asset="${X402_CONFIG.asset}" amount="${priceAtomic}" payTo="${X402_CONFIG.payTo}"`,
      "content-type": "application/json; charset=utf-8"
    },
    body: {
      error: "Payment Required",
      resource,
      accepts: [
        {
          scheme: "exact",
          network: X402_CONFIG.network,
          asset: X402_CONFIG.asset,
          payTo: X402_CONFIG.payTo,
          amount: priceAtomic,
          maxTimeoutSeconds: 300
        }
      ],
      extensions: {
        bazaar: BAZAAR_DISCOVERY_METADATA
      }
    }
  };
}

/**
 * Validates a payment signature or proof header.
 * For testnet and mock scenarios, validates the signature payload format.
 */
/**
 * Builds the standard payment requirements object for a given resource and price.
 */
export function buildPaymentRequirements(resource, priceAtomic = X402_CONFIG.defaultPriceAtomic) {
  return {
    scheme: "exact",
    network: X402_CONFIG.network,
    amount: priceAtomic,
    asset: X402_CONFIG.asset,
    payTo: X402_CONFIG.payTo,
    maxTimeoutSeconds: 300,
    extra: {
      name: "USDC",
      version: "2",
      assetTransferMethod: "eip3009"
    }
  };
}

/**
 * Validates that an accepted requirement in a payment payload satisfies server requirements.
 */
export function validatePaymentPayloadAgainstRequirements(paymentPayload, requirements) {
  if (!paymentPayload || typeof paymentPayload !== "object") {
    return { valid: false, reason: "Payment payload is missing or not an object." };
  }
  const accepted = paymentPayload.accepted;
  if (!accepted || typeof accepted !== "object") {
    return { valid: false, reason: "Payment payload is missing 'accepted' requirements object." };
  }
  if (accepted.scheme !== requirements.scheme) {
    return { valid: false, reason: `Payment scheme '${accepted.scheme}' does not match required '${requirements.scheme}'.` };
  }
  if (accepted.network !== requirements.network) {
    return { valid: false, reason: `Payment network '${accepted.network}' does not match required '${requirements.network}'.` };
  }
  if (typeof accepted.asset !== "string" || accepted.asset.toLowerCase() !== requirements.asset.toLowerCase()) {
    return { valid: false, reason: "Payment asset does not match required contract address." };
  }
  if (typeof accepted.payTo !== "string" || accepted.payTo.toLowerCase() !== requirements.payTo.toLowerCase()) {
    return { valid: false, reason: "Payment recipient does not match server receiving address." };
  }

  // Treat payment fields as untrusted input. BigInt throws on malformed values,
  // which would otherwise turn a rejected proof into an HTTP 500 response.
  const amount = accepted.amount;
  const requiredAmount = requirements.amount;
  if (typeof amount !== "string" || !/^\d+$/.test(amount)) {
    return { valid: false, reason: "Payment amount must be a non-negative integer string." };
  }
  if (typeof requiredAmount !== "string" || !/^\d+$/.test(requiredAmount)) {
    return { valid: false, reason: "Server payment amount configuration is invalid." };
  }
  if (BigInt(amount) < BigInt(requiredAmount)) {
    return { valid: false, reason: `Payment amount ${amount} is less than required ${requiredAmount}.` };
  }
  const payload = paymentPayload.payload;
  if (!payload || typeof payload !== "object" || !payload.signature) {
    return { valid: false, reason: "Missing cryptographic payment authorization signature in payload." };
  }
  return { valid: true };
}

/**
 * Verifies and optionally settles an x402 payment according to the protocol specification.
 * In live mode, contacts the facilitator for /verify and /settle.
 * In mock/simulated mode, validates payload structure and reports simulated: true, settled: false.
 */
const DEFAULT_X402_REPLAY_GUARD = createInMemoryX402ReplayGuard();

export async function verifyPaymentProof(paymentProofHeader, resource, priceAtomic = X402_CONFIG.defaultPriceAtomic, options = {}) {
  if (!paymentProofHeader) {
    return { valid: false, settled: false, reason: "Missing Payment-Signature or X-Payment header." };
  }

  const requirements = buildPaymentRequirements(resource, priceAtomic);

  // Parse header
  let paymentPayload = null;
  try {
    if (typeof paymentProofHeader === "object" && paymentProofHeader !== null) {
      paymentPayload = paymentProofHeader;
    } else if (paymentProofHeader.startsWith("{")) {
      paymentPayload = JSON.parse(paymentProofHeader);
    } else {
      const match = paymentProofHeader.match(/sig="?([^";]+)"?/i);
      const signature = match ? match[1] : paymentProofHeader.startsWith("0x") ? paymentProofHeader : null;
      if (signature) {
        paymentPayload = {
          x402Version: 2,
          accepted: {
            scheme: requirements.scheme,
            network: requirements.network,
            asset: requirements.asset,
            payTo: requirements.payTo,
            amount: requirements.amount
          },
          payload: { signature }
        };
      }
    }
  } catch {
    return { valid: false, settled: false, reason: "Malformed payment proof header." };
  }

  if (!paymentPayload) {
    return { valid: false, settled: false, reason: "Invalid payment proof token format." };
  }

  // 1. Structural and requirement validation
  const validation = validatePaymentPayloadAgainstRequirements(paymentPayload, requirements);
  if (!validation.valid) {
    return { valid: false, settled: false, reason: validation.reason };
  }

  const isLive = Boolean(options.liveFacilitator || process.env.X402_LIVE_SETTLEMENT === "true");
  const facilitatorUrl = options.facilitatorUrl || process.env.X402_FACILITATOR_URL;

  // 2. Live mode: Must verify and settle via facilitator. NEVER fall back to mock.
  if (isLive) {
    if (!facilitatorUrl) {
      return { valid: false, settled: false, mode: "live_facilitator", reason: "Facilitator URL not configured for live settlement." };
    }

    // Live mode accepts only the x402 V2 exact-EVM EIP-3009 payload shape.
    // The facilitator remains responsible for cryptographic and on-chain verification.
    const authorizationCheck = validateEip3009Authorization(paymentPayload, requirements);
    if (!authorizationCheck.valid) {
      return { valid: false, settled: false, mode: "live_facilitator", reason: authorizationCheck.reason };
    }

    const replayGuard = options.replayGuard || DEFAULT_X402_REPLAY_GUARD;
    if (
      !replayGuard ||
      typeof replayGuard.claim !== "function" ||
      typeof replayGuard.release !== "function" ||
      typeof replayGuard.markSettled !== "function"
    ) {
      return { valid: false, settled: false, mode: "live_facilitator", reason: "Replay protection store is unavailable; payment was not submitted." };
    }

    // Reserve before any facilitator call. The default store makes this claim atomic
    // within one Node.js process; production multi-instance deployments need shared storage.
    let reservation;
    try {
      reservation = await replayGuard.claim(authorizationCheck.key);
    } catch {
      return { valid: false, settled: false, mode: "live_facilitator", reason: "Replay protection store failed; payment was not submitted." };
    }
    if (!reservation?.claimed) {
      const status = reservation?.status || "already_seen";
      return {
        valid: false,
        settled: false,
        mode: "live_facilitator",
        reason: status === "capacity"
          ? "Replay protection store is at capacity; payment was rejected fail-closed."
          : "Duplicate or replayed EIP-3009 authorization rejected (state: " + status + ")."
      };
    }

    const releaseReservation = async () => {
      try {
        await replayGuard.release(authorizationCheck.key);
      } catch {
        // A failed release must never turn a rejected payment into an accepted one.
      }
    };
    const fetchFn = options.fetchImpl || fetch;

    // Step A: facilitator /verify.
    let verifyData;
    try {
      const verifyRes = await fetchFn(facilitatorUrl + "/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements: requirements })
      });
      if (!verifyRes || !verifyRes.ok) {
        await releaseReservation();
        return { valid: false, settled: false, mode: "live_facilitator", reason: "Facilitator /verify HTTP error " + (verifyRes ? verifyRes.status : "offline") };
      }
      verifyData = await verifyRes.json();
    } catch (err) {
      await releaseReservation();
      return { valid: false, settled: false, mode: "live_facilitator", reason: "Facilitator /verify network failure: " + err.message };
    }

    if (!verifyData || verifyData.isValid !== true) {
      await releaseReservation();
      return {
        valid: false,
        settled: false,
        mode: "live_facilitator",
        reason: verifyData?.invalidReason || verifyData?.invalidMessage || "Payment authorization verification failed."
      };
    }

    // Step B: /settle. Keep the reservation on ambiguous transport failures because
    // the facilitator may have broadcast the transaction before its response was lost.
    let settleData;
    try {
      const settleRes = await fetchFn(facilitatorUrl + "/settle", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements: requirements })
      });
      if (!settleRes || !settleRes.ok) {
        return { valid: false, settled: false, mode: "live_facilitator", reason: "Facilitator /settle HTTP error " + (settleRes ? settleRes.status : "offline") + "; authorization remains reserved pending reconciliation." };
      }
      settleData = await settleRes.json();
    } catch (err) {
      return { valid: false, settled: false, mode: "live_facilitator", reason: "Facilitator /settle network failure: " + err.message + "; authorization remains reserved pending reconciliation." };
    }

    if (settleData?.success === false) {
      await releaseReservation();
      return {
        valid: false,
        settled: false,
        mode: "live_facilitator",
        reason: settleData.errorReason || "Settlement failed on-chain."
      };
    }

    // An incomplete response is ambiguous, so keep the reservation for reconciliation.
    if (settleData?.success !== true || typeof settleData.transaction !== "string" || !settleData.transaction) {
      return {
        valid: false,
        settled: false,
        mode: "live_facilitator",
        reason: "Facilitator returned an incomplete settlement response; authorization remains reserved pending reconciliation."
      };
    }

    let replayGuardWarning;
    try {
      await replayGuard.markSettled(authorizationCheck.key);
    } catch {
      // The facilitator has already confirmed settlement. Keep the reservation pending
      // (so this process still rejects retries) but do not misreport a completed payment
      // as unsettled or encourage the client to submit it again.
      replayGuardWarning = "Facilitator confirmed settlement, but the replay store could not mark the reservation settled. Reconcile before restarting or retrying.";
    }

    return {
      valid: true,
      mode: "live_facilitator",
      ...(replayGuardWarning ? { replayGuardWarning } : {}),
      settlement: {
        settled: true,
        simulated: false,
        network: settleData.network || requirements.network,
        amount: requirements.amount,
        asset: requirements.asset,
        recipient: requirements.payTo,
        transaction: settleData.transaction,
        payer: settleData.payer || verifyData.payer || paymentPayload.payload.authorization.from,
        timestamp: new Date().toISOString()
      }
    };
  }

  // 3. Mock / Simulated mode: Explicitly report simulated: true and settled: false
  // Never trust caller-supplied txHash as settlement proof!
  return {
    valid: true,
    mode: "mock_simulation",
    settlement: {
      settled: false, // explicitly false to prevent false claims
      simulated: true,
      network: requirements.network,
      amount: requirements.amount,
      asset: requirements.asset,
      recipient: requirements.payTo,
      timestamp: new Date().toISOString()
    }
  };
}

/**
 * PayBox Marketplace Integration Adapter
 */
export const payboxIntegration = Object.freeze({
  manifest: {
    id: "payguard",
    name: "PayGuard",
    version: "0.1.0",
    description: "Security-focused x402 sentinel and payment policy guard for PayBox AI agents.",
    provider: "PayGuard",
    protocols: ["mcp", "x402"],
    homepage: "https://paybox.sh",
    bazaar: BAZAAR_DISCOVERY_METADATA
  },
  plugin,
  build402Challenge,
  verifyPaymentProof
});

export default payboxIntegration;

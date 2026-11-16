# x402 V2 Replay Protection — Exact EVM / EIP-3009

## Scope

PayGuard currently advertises the x402 V2 exact EVM scheme with the EIP-3009 transfer method. This implementation uses the protocol's existing payload.authorization.nonce field. It does not add a custom nonce field or change the x402 wire format.

## Replay identity

The local replay key is derived from:
- CAIP-2 network identifier
- Token contract (accepted.asset)
- Authorizer (payload.authorization.from)
- EIP-3009 nonce (payload.authorization.nonce)

The same nonce may legitimately exist for a different authorizer, token contract, or chain, so those values are part of the key.

## Live payment flow

1. Validate the x402 V2 EIP-3009 payload shape and authorization fields.
2. Atomically reserve the replay identity before contacting the facilitator.
3. Call facilitator /verify.
4. Release the reservation when verification is definitively rejected or fails before settlement is attempted.
5. Call facilitator /settle only after successful verification.
6. Mark the identity settled after a successful settlement response.
7. Keep the reservation pending if settlement outcome is ambiguous (for example, a connection drops after the facilitator may have broadcast). Reconcile before retrying.

The facilitator remains responsible for cryptographic signature verification, balance and validity-window checks, and on-chain settlement. The token contract's EIP-3009 nonce-consumption rule is the authoritative on-chain replay protection.

## Deployment boundary

The default replay guard is in-memory and process-local. Its claim operation is atomic within one Node.js process, which protects same-process concurrent requests. It is not a distributed lock:
- It does not coordinate separate serverless or horizontally scaled instances.
- Its state is lost when the process restarts.
- It fails closed when its configured entry capacity is exhausted.
- Ambiguous settlement reservations remain pending in that process and require operator reconciliation.

Before enabling paid x402 endpoints across multiple production instances, replace the default guard with a durable shared adapter whose claim operation is atomic (for example, a database unique constraint or Redis SET NX with carefully designed persistence). Settlement reconciliation must be designed alongside that adapter.

## Test coverage

The regression suite covers duplicate authorization, concurrent duplicate requests, release after definite facilitator verification rejection, retention after ambiguous settlement transport failure, and rejection of live payloads missing EIP-3009 authorization.

Mock facilitator tests validate PayGuard's request orchestration only. They do not prove a real facilitator or Base Sepolia transaction works end-to-end.
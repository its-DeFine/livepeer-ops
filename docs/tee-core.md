# Payments “TEE core” (roadmap)

This doc defines the next step beyond “TEE signer”: make the **enclave the final authority** for ledger updates + payouts, so we can attest not just *where the key lives*, but *what payout logic ran*.

## Problem this solves

With a TEE signer only:
- The signing key is protected from exfiltration.
- But a compromised host/backend can still instruct the signer to pay the wrong recipient/amount (unless the signer has strict policy).

With a TEE core:
- The enclave owns the **ledger state** and constructs payouts from that state.
- The host becomes a **proxy/transport layer** (HTTP + chain RPC + storage), not the source of truth.

## Trust model (practical)

- **Untrusted host**: can read/modify local files, intercept HTTP, call the enclave RPC.
- **Trusted enclave**: holds the signing key and enforces policy, produces an attestation doc.
- **Trusted external**: Arbitrum (for settlement), AWS KMS (for unsealing/sealing keys under attestation constraints).

Note: a TEE core can prove “this code ran”, but it cannot prove inputs are truthful unless inputs are also verifiable (signed by trusted reporters or cross-checked on-chain).

## High-level architecture

- **Host (FastAPI)**:
  - receives workload + session events
  - talks to chain RPC (estimate gas, nonce, receipts)
  - broadcasts signed raw transactions
  - persists encrypted enclave state blobs (and audit logs)
  - exposes public HTTP endpoints (and serves `/api/tee/*` by proxying enclave info)

- **Enclave (TEE core service)**:
  - holds ETH signing key (KMS-unsealed) and returns attestation doc
  - maintains ledger balances + pending payouts
  - validates payout requests against ledger/policy
  - constructs TicketBroker tickets and signs:
    - EIP-191 ticket signatures
    - the Ethereum transaction(s) that redeem tickets
  - returns **signed raw tx** to host for broadcast

## State + sealing

The enclave needs persistence across restarts (balances, pending tx hashes, last processed event id).

Baseline approach:
- Host stores an encrypted blob (e.g. `data/tee_state.bin`).
- Enclave unseals a symmetric “state key” from KMS using Recipient attestation.
- Enclave decrypts/encrypts the state blob with AEAD (integrity checked).

Open issue: **rollback protection** (host can replay an old blob). Mitigation options:
- store a monotonic counter externally (DynamoDB, S3 object versioning + signed manifests, or on-chain anchoring)
- derive payout idempotency from on-chain state (avoid double-pays by verifying tx hashes / nonce usage)

## Proposed vsock RPC (length-prefixed JSON)

This reuses the framing from `payments/signer.py`.

Core methods (draft):
- `status` → `{ address, attestation_available, ledger_root?, version }`
- `attestation` (nonce optional) → `{ document_b64 }`
- `load_state` → host provides encrypted blob; enclave returns `{ ok, ledger_root }`
- `export_state` → enclave returns encrypted blob `{ blob_b64, ledger_root }`
- `apply_event` → `{ ok, ledger_root }` (workload/session credit events; ideally signed by reporters)
- `prepare_payouts` → input payouts + chain params; returns `{ raw_tx }` (or multiple) and a `payout_id`
- `confirm_payout` → input receipt; enclave debits balances and clears pending

## Next implementation milestones

1) Enclave signer policy (already started): restrict signing to TicketBroker + allowlisted recipients/limits.
2) Add TEE core service (local TCP first, then vsock/enclave):
   - implement minimal ledger + payout queue inside the service
   - host forwards credits + asks for payouts
3) Add state sealing and restart safety (idempotency + rollback mitigation).


# Security review: Payments TEE (Nitro Enclaves)

This document reviews the security posture of the current “TEE signer” milestone and defines what we need to ship the next milestone: **TEE core / payments authority**.

## Scope

In-scope components:
- **Host (untrusted)**: Payments backend HTTP API, chain RPC client, state persistence, log collection, `vsock-proxy` to AWS KMS.
- **Enclave (trusted)**: signer service (and next: core service) that:
  - holds the ETH key in enclave memory
  - exposes signing / payout RPC over vsock
  - returns an AWS Nitro Enclaves attestation document
  - unseals secrets via AWS KMS *Recipient attestation*

Out of scope (but relevant dependencies):
- Arbitrum / settlement chain finality
- AWS account security posture (break-glass users, MFA, CloudTrail)
- Edge/orchestrator security (workload attestations / artifact integrity)

## Threat model (practical)

### Trust assumptions
- The **host OS** can be compromised (RCE, container escape, disk tampering).
- The **enclave** is protected from host inspection/modification by Nitro Enclaves isolation.
- AWS KMS *Recipient attestation* is trusted to enforce “only enclaves with measurement X can decrypt”.

### Adversaries
- **Remote attacker**: can hit public HTTP endpoints; may obtain API tokens if leaked.
- **Host attacker**: gains arbitrary code execution on the EC2 instance (root-level).
- **Operator error**: misconfiguration (debug enclave, wrong KMS policy, permissive signer policy).

## Current milestone: “TEE signer”

### What we get
- **Key custody**: the ETH private key exists in plaintext only inside enclave memory.
- **Code integrity**: external parties can verify the enclave image by validating the attestation document measurement (PCR0/ImageSha384).
- **Reduced blast radius** vs. “key in backend container”: a web RCE cannot trivially exfiltrate the signing key.

### What we do *not* get (yet)
- A compromised host can still attempt to instruct the signer to sign harmful transactions **unless** the signer enforces strict policy.
- The enclave cannot prove that **credits** were legitimate (inputs are not verifiable by default).
- Without state sealing + rollback protection, the host can replay old state.

## Key custody + unsealing (KMS)

### Current approach (recommended)
- Generate an enclave-only key using KMS `GenerateDataKey` from inside the enclave.
- Persist only the **KMS ciphertext blob** on the host.
- On restart, pass the ciphertext blob back into the enclave and decrypt via KMS with *Recipient attestation*.

### Security notes
- **Debug enclaves are not acceptable for production**: KMS recipient-attested operations are rejected for `--debug-mode`. Treat this as a feature; debug mode also weakens the trust story.
- The host passes temporary **IMDS credentials** to the enclave to call KMS. This does not protect against a host compromise (host already has those creds), but is necessary because the enclave cannot access IMDS directly.

## Signer policy (transaction-level)

The signer must assume the host can be malicious. The enclave should enforce:
- `chainId` fixed (ex: Arbitrum mainnet `42161`)
- `to` fixed to the expected contract(s) (ex: TicketBroker)
- `data` selectors restricted (ex: `redeemWinningTicket`, `batchRedeemWinningTickets`, optional `fundDeposit`)
- recipient allowlist (or mapping) and strict limits (`max_face_value`, `max_batch_total`)

This reduces theft risk if the HTTP backend is compromised.

## Next milestone: “TEE core / payments authority”

Goal: make the enclave the authority for **balances + payout construction**, not just signature generation.

### Why this matters
With signer-only, the host can potentially:
- craft valid TicketBroker calls that send value to an allowlisted but incorrect recipient
- choose payout amounts within allowed limits (still theft if policy is permissive)

With a TEE core, the enclave:
- maintains balances
- selects the recipient deterministically (stored mapping)
- constructs the payout transaction(s)
- only debits balances when confirming a known, successfully-mined tx

Host responsibility becomes:
- forwarding events to the enclave
- broadcasting enclave-signed raw tx
- persisting encrypted enclave state blobs for restart

In this repo’s current implementation, the host forwards credit events by tailing the append-only **ledger journal**
(`PAYMENTS_LEDGER_JOURNAL_PATH`) and calling `credit` on the TEE core with a stable `event_id` derived from each journal line.

### Required security properties
- **Recipient immutability**: once an orchestrator payout address is registered in enclave state, the host cannot redirect payments.
- **Balance non-negativity**: enclave never signs a payout exceeding internal balance.
- **Idempotency**: payout confirmations must be tied to enclave-created tx hashes to prevent double-debit/double-pay.
- **State sealing**: balances/pending payouts survive restarts.
- **Rollback resistance** (open issue): prevent host from replaying an older sealed blob.

## State sealing + rollback risk

Baseline sealing:
- Enclave holds a symmetric “state key” (generated/unsealed via KMS recipient attestation).
- Enclave encrypts state with AEAD (AES-GCM) and returns `blob + key_ciphertext`.
- Host stores the blob, but cannot decrypt or forge it.

Rollback remains possible if the host can replace the stored blob with an older one.

Mitigation options (choose one for production):
- Store a monotonic counter externally (DynamoDB with conditional writes, S3 object versioning + signed manifests).
- Anchor state roots on-chain (periodic commit), then refuse to load older roots.
- Derive idempotency from chain state (track nonce/tx-hash and require verifiable confirmations).

## Attestation verification

We currently expose the Nitro Enclave attestation document via the Payments API.

For production readiness we need:
- a documented verifier flow (operator/client) that:
  - validates COSE signature chain to AWS Nitro root
  - checks PCR0/ImageSha384 matches expected EIF measurement
  - optionally validates `user_data` includes the signer address
- an operational process for measurement pinning and safe rollouts (allowlist new PCR0s before deployment).

## Operational checklist (production)

- KMS key policy:
  - allow only `kms:Decrypt`/`kms:GenerateDataKey` for the instance role
  - require Recipient attestation measurement match
  - no other principals can decrypt
- Enclave run:
  - **no debug mode**
  - dedicated CID and vsock port
- Logging:
  - record every credit event and every payout confirmation (append-only audit log on host)
  - record tx hashes and recipient addresses for later reconciliation
- Key rotation:
  - support provisioning a new ciphertext blob and draining old balances (dual-run window)

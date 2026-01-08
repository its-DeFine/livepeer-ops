# Orchestrator credential (non-transferable NFT)

This document defines the credential used to verify orchestrators for
private balance proofs and API access without repeated wallet signatures.

## Goals

- Provide a verifiable on-chain identity for orchestrators.
- Allow rapid revocation/rotation by a cold owner address.
- Avoid exposing per-orchestrator balances publicly.

## Contract model

- **Non-transferable**: only `mint` and `burn` are allowed.
  - `transferFrom`/`safeTransferFrom` must revert unless the target is
    `0x0000000000000000000000000000000000000000`, which is treated as burn.
- **Owner**: the orchestrator address (cold wallet).
- **Delegate**: a hot wallet used for API authentication.
  - Owner can rotate the delegate at any time.
  - Delegate may burn to revoke immediately if compromised.
- **Expiry**: none (credential is valid until burned).

## Minting / eligibility

Minting is permissionless but gated by on-chain checks:

- `registry.isRegistered(owner)` (optional registry contract)
- `bondingManager.transcoderTotalStake(owner) >= minStake`

The reference implementation lives in `contracts/OrchestratorCredential.sol`.

## Auth flow (private endpoints)

1) Client requests a nonce from the backend.
2) Delegate signs the nonce + orchestrator_id + owner + delegate + expiry.
3) Backend verifies on-chain ownership + delegate binding.
4) Backend issues an access token (short-lived; TTL configurable).
5) Private endpoints accept the access token (no repeated wallet signatures).

API endpoints:

- `POST /api/orchestrators/{orchestrator_id}/credential/nonce`
- `POST /api/orchestrators/{orchestrator_id}/credential/token`

Config:

- `PAYMENTS_ORCHESTRATOR_CREDENTIAL_CONTRACT_ADDRESS`
- `PAYMENTS_ORCHESTRATOR_CREDENTIAL_NONCE_TTL_SECONDS` (default 300)
- `PAYMENTS_ORCHESTRATOR_CREDENTIAL_TOKEN_TTL_SECONDS` (default 900)

## Revocation / rotation

- Owner can rotate delegate or burn the credential.
- Delegate can burn for emergency revocation.
- Access tokens can be short-lived; after burn/rotation, new tokens cannot be issued.

## API usage

Private endpoints (per-orchestrator ledger proofs, payout detail views) require
the credential. Public endpoints (audit log, checkpoints, attestation) remain
unauthenticated.

## Security notes

- Emit explicit events: `CredentialMinted`, `DelegateUpdated`,
  `CredentialBurned`.
- Include replay protection for auth nonces (single-use + TTL).

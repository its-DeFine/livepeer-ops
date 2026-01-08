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

Minting requires a signed authorization from the registry/oracle (EIP-712),
or a call from a registry contract. The authorization should bind:

- owner address
- delegate address
- orchestrator_id
- issuance timestamp and nonce

## Auth flow (private endpoints)

1) Client requests a nonce from the backend.
2) Delegate signs the nonce.
3) Backend verifies on-chain ownership + delegate binding.
4) Backend issues a short-lived access token (JWT/session).
5) Private endpoints accept the access token (no repeated wallet signatures).

## Revocation / rotation

- Owner can rotate delegate or burn the credential.
- Delegate can burn for emergency revocation.
- Access tokens are short-lived; after burn/rotation, new tokens cannot be issued.

## API usage

Private endpoints (per-orchestrator ledger proofs, payout detail views) require
the credential. Public endpoints (audit log, checkpoints, attestation) remain
unauthenticated.

## Security notes

- Emit explicit events: `CredentialMinted`, `DelegateUpdated`,
  `CredentialBurned`.
- Include replay protection for mint authorizations (nonce + expiry).

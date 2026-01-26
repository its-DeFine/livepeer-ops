# Overview: Livepeer Ops Backend

This repo provides a self-hosted backend that Livepeer participants can run to coordinate:

- orchestrator onboarding/registry metadata
- usage metering (time-based workloads and/or session events)
- a credits ledger + payout loop (optional)
- optional transparency and attestation for “trust but verify” operation

The default deployment is intentionally minimal: local JSON state on disk, dry-run payouts by default, and optional modules gated behind environment variables and Compose profiles.

## Components

- **HTTP API (FastAPI)**: orchestrator registry + workload/session ingestion + ledger views.
- **Ledger + payout loop**: credits balances and (when enabled) performs on-chain settlement.
- **Audit log (append-only)**: emits balance-changing events and can be verified offline.
- **Optional TEE signer/core**:
  - signer mode: keeps the transaction signing key outside the network-facing API process
  - core mode: makes the enclave the final authority for ledger + payout policy
- **Optional witness tooling**: publishes transparency checkpoints on-chain and verifies the backend’s claims.

## Typical flows

### 1) Orchestrator onboarding

1. Orchestrator registers an `orchestrator_id` and payout address.
2. Optional: an operator/watcher pushes health snapshots (instead of the backend polling every orchestrator).
3. Optional: orchestrator mints a non-transferable credential and binds a delegate hot wallet for API auth.

### 2) Usage metering → credits

Depending on your workload type:

- **Time-based workloads**: post a workload event with duration and metadata; the backend credits the ledger immediately.
- **Session events**: edges report “start/heartbeat/end”; the backend credits by connected session time.

All balance changes are logged and can be audited.

### 3) Credits → payouts (optional)

When payout mode is enabled, the backend periodically:

1. computes owed balances (above thresholds)
2. constructs settlement transactions (ETH transfer or TicketBroker redemption)
3. broadcasts and waits for receipts
4. clears ledger entries only after confirmed success

### 4) Transparency + attestations (optional)

If using a signer/core enclave, the backend can expose:

- attestation documents (`/api/tee/*`) so partners can verify the enclave identity
- transparency endpoints so partners can verify append-only audit history
- on-chain checkpoints so a third party can witness the latest state pointer

## Deep dives

- Minimal deploy guide: `docs/community-minimal-deploy.md`
- Orchestrator credential: `docs/orchestrator-credential.md`
- TEE signer/attestation: `docs/tee-attestation.md`
- TEE core: `docs/tee-core.md`
- Transparency + checkpoints: `docs/tee-transparency.md`
- Session billing: `docs/session-billing.md`

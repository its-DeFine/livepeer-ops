# ZK ledger proof statement (v1)

This document defines a **ZK proof statement** for the Payments TEE core that
proves ledger transitions are correct, credits are signed, and payouts are bound
to on-chain transaction hashes. It **complements** Nitro attestation (key custody)
and the transparency log (append-only evidence).

## Goals

- Prove ledger transitions are correct (no negative balances, deterministic updates).
- Require **signed credit events** from approved reporter keys.
- Bind each payout to its **transaction hash** (tx hash commitment).
- Publish **public balances** for auditability.

## Non-goals (v1)

- Balance privacy (we explicitly publish balances).
- On-chain verification of the ZK proof (optional later).
- Proving tx inclusion on-chain (we bind to tx hash; receipts can be verified off-chain).

## Statement (public balances)

Public inputs:
- `R_prev`: previous ledger state root
- `R_next`: new ledger state root
- `H_prev`: previous audit head hash
- `H_next`: new audit head hash
- `policy_hash`: hash of payout policy enforced
- `reporter_pubkeys`: approved credit reporter keys
- `chain_id`, `ticketbroker_contract`
- `payout_commitment`: commitment to all payout tx hashes + amounts + recipients
- `balances_prev_public`: list of (orchestrator_id, recipient, balance_wei)
- `balances_next_public`: same list after transition
- `total_supply_prev`, `total_supply_next`

Note: for full transparency publish all balances. If you publish a subset,
`total_supply_*` still binds the aggregate but does not reveal distribution.

Private inputs (witness):
- `S_prev`: full ledger state (balances + registered payout addresses)
- `E`: ordered batch of events (credits, payouts)
- `sigs`: reporter signatures for credit events
- `payouts`: each payout includes {event_id, orchestrator_id, recipient, amount_wei, tx_hash}

Constraints:
1) `hash(S_prev) == R_prev`
2) `balances_prev_public` entries match `S_prev`
3) For each credit event:
   - signature verifies under `reporter_pubkeys`
   - event sequence is strictly increasing
4) For each payout event:
   - recipient equals registered payout address in `S_prev`
   - amount <= available balance at debit time
   - payout item is included in `payout_commitment`
5) Apply events in order to derive `S_next`
6) All balances in `S_next` are non-negative
7) `balances_next_public` entries match `S_next`
8) `total_supply_next = total_supply_prev + sum(credits) - sum(payouts)`
9) `hash(S_next) == R_next`
10) Audit entries derived from events append `H_prev -> H_next`

## Canonical data model + hashing

This section defines the **minimal proto** (stable hashing + ordering) used by
the statement. The goal is deterministic hashing compatible with the current
TEE core implementation.

### Normalization

- Addresses are lowercase hex.
- `orchestrator_id` and `event_id` are UTF-8 strings.
- `orch_hash = keccak(text=orchestrator_id)`
- `event_hash = keccak(text=event_id)`

### Credit signature (matches enclave-core)

Credit signature message hash:

```
msg_hash = keccak(encodePacked(
  "payments-tee-core:credit:v1",
  orch_hash,
  recipient,
  amount_wei,
  event_hash
))
```

The reporter signature is `eth_sign` (EIP-191) over `msg_hash`.

### Ledger leaf + root

Ledger leaf hash:

```
leaf_hash = keccak(abi.encode(
  "payments-tee-core:ledger:v1",
  orch_hash,
  recipient,
  balance_wei
))
```

Ledger root is computed over all leaves, sorted by `orch_hash` ascending,
using the same Merkle scheme as the transparency log:

- `leaf_node = keccak(0x00 || leaf_hash)`
- `node = keccak(0x01 || left || right)`

### Audit leaf + head hash

Audit leaves are derived from the same event data used by the transparency log,
but encoded in a circuit-friendly form.

```
audit_leaf = keccak(abi.encode(
  "payments-tee-core:audit-leaf:v1",
  seq,
  event_hash,
  delta_wei,
  balance_wei,
  orch_hash,
  recipient
))
```

The audit head hash `H_next` is the **hash-chain head** of audit entry hashes,
and the Merkle root is computed over `audit_leaf` values using the same
0x00/0x01 prefix scheme. The proof must show that applying events yields
`H_prev -> H_next`.

### Payout commitment

Each payout item hash:

```
payout_item = keccak(abi.encode(
  "payments-tee-core:payout:v1",
  event_hash,
  orch_hash,
  recipient,
  amount_wei,
  tx_hash
))
```

`payout_commitment` is the Merkle root over `payout_item` hashes using the
same 0x00/0x01 prefix scheme.

### Policy hash

`policy_hash` is a stable hash of the policy config used by the TEE core. It
should be computed with a typed encoding (ABI) and include at minimum:

- policy version
- chain_id
- ticketbroker_contract
- payout limits (if any)

## Minimal proof bundle (protocol)

Proofs are published as **bundles** that a verifier can fetch and validate.
This format is designed to be forward-compatible and JSON-friendly.

```
{
  "schema": "payments-tee-core:zk-proof:v1",
  "seq_start": 101,
  "seq_end": 150,
  "created_at": "2026-01-08T00:00:00Z",
  "public_inputs": {
    "R_prev": "0x...",
    "R_next": "0x...",
    "H_prev": "0x...",
    "H_next": "0x...",
    "policy_hash": "0x...",
    "payout_commitment": "0x...",
    "chain_id": 42161,
    "ticketbroker_contract": "0x..."
  },
  "balances_prev_public": [
    {"orchestrator_id": "orch_1", "recipient": "0x...", "balance_wei": "123"}
  ],
  "balances_next_public": [
    {"orchestrator_id": "orch_1", "recipient": "0x...", "balance_wei": "456"}
  ],
  "total_supply_prev": "123",
  "total_supply_next": "456",
  "payouts": [
    {"event_id": "payout:0x...", "recipient": "0x...", "amount_wei": "100", "tx_hash": "0x..."}
  ],
  "proof": {
    "system": "sp1",
    "version": "x.y.z",
    "proof_b64": "..."
  }
}
```

Suggested endpoints:
- `GET /api/transparency/tee-core/zk/status` (latest proof metadata)
- `GET /api/transparency/tee-core/zk/proof?seq_start=...&seq_end=...`

## Staged implementation plan

### Phase 0 (now): hardening without ZK
- Require credit signatures (`require_credit_signature=1`).
- Add rollback protection (DynamoDB conditional writes or S3 versioned manifest).
- Publish `policy_hash`, `ledger_root`, and `payout_commitment` in the audit log or status.

### Phase 1: proof-ready commitments
- Add deterministic ledger root (sorted leaves + explicit hashing).
- Add payout commitment and audit leaf commitments to the transparency log.
- Expose `ledger_root_prev`/`ledger_root_next` in `/api/tee/core/status`.

### Phase 2: off-chain proofs
- Implement a zkVM circuit (SP1/Risc0) for the statement above.
- Build a prover sidecar (host or witness) that:
  - snapshots `S_prev`, `E`, `S_next`
  - emits a proof bundle
  - stores it under `data/zk/` and exposes it via the API

### Phase 3: optional on-chain verification
- Deploy a verifier contract for the proof system.
- Store the latest proof commitment on-chain (similar to the audit checkpoint).

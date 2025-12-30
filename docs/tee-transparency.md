# Payments TEE transparency (audit log + on-chain checkpoints)

This repo ships a **TEE-signed, append-only audit log** plus an **on-chain checkpoint** mechanism so partners can verify:

- which TEE identity is producing financial events (via Nitro attestation user_data binding)
- every balance-changing event (signed audit entries)
- that the audit history is append-only (prev_hash chain + Merkle root)
- that a third party can witness the latest state on-chain (checkpoint contract)

## Public endpoints (no token)

- `GET /api/tee/core/attestation` (Nitro attestation doc)
- `GET /api/transparency/tee-core/audit/status`
- `GET /api/transparency/tee-core/audit/checkpoint`
- `GET /api/transparency/tee-core/audit/proof?event_id=...`
- `GET /api/transparency/tee-core/log`
- `GET /api/transparency/tee-core/receipt?event_id=...`

These endpoints are rate-limited and intentionally unauthenticated so **external witnesses** can operate without operator-issued tokens.

## Checkpoint commitment format

The on-chain contract stores `(seq, headHash)` per audit signer. In this system `headHash` is a **commitment** to both:

- the hash-chain head (`chain_head_hash`, the last audit entry hash)
- the Merkle root (`merkle_root`, computed over audit entry hashes)

Commitment:

```
head_hash = keccak(encodePacked(
  "payments-tee-core:checkpoint-head:v1",
  chain_head_hash,
  merkle_root
))
```

The enclave signs the checkpoint message hash:

```
keccak(encodePacked(
  "payments-tee-core:checkpoint:v1",
  auditAddress,
  seq,
  head_hash,
  chainId,
  contractAddress
))
```

The minimal contract verifies that signature and stores the latest checkpoint.

## Witness publishing (recommended)

### One-shot publish

```
python3 scripts/publish_tee_core_checkpoint.py \
  --backend-url https://HOST:8081 \
  --rpc-url $RPC_URL \
  --contract-address $CHECKPOINT_CONTRACT \
  --publisher-private-key $WITNESS_KEY
```

### Continuous witness loop

```
python3 scripts/publish_tee_core_checkpoint.py \
  --watch \
  --interval-seconds 600 \
  --backend-url https://HOST:8081 \
  --rpc-url $RPC_URL \
  --contract-address $CHECKPOINT_CONTRACT \
  --publisher-private-key $WITNESS_KEY
```

### Docker compose sidecar (optional)

`docker-compose.yml` includes an optional `payments-checkpoint-witness` service under the `witness` profile:

```
CHECKPOINT_RPC_URL=...
CHECKPOINT_CONTRACT_ADDRESS=0x...
CHECKPOINT_PUBLISHER_PRIVATE_KEY=0x...
CHECKPOINT_CHAIN_ID=421614   # ex: Arbitrum Sepolia

docker compose --profile witness up -d
```

## Partner verifier CLI

Install:

```
python3 -m pip install -r scripts/requirements-verifier.txt
```

Verify checkpoint + attestation binding + (optionally) an event proof:

```
python3 scripts/verify_transparency.py \
  --backend-url https://HOST:8081 \
  --rpc-url $RPC_URL \
  --contract-address $CHECKPOINT_CONTRACT \
  --event-id workload:WORKLOAD_ID
```

Optional:

- `--verify-log` downloads the full log and verifies signatures + prev-hash chaining.
- `--pcr0-allowlist` lets partners pin expected measurements (comma-separated hex).
- `--nitro-root-pem` points at a trusted Nitro root PEM for cert-chain verification.


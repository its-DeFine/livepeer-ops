# TEE signer + attestation (design)

Goal: keep the **payments signing key** out of the network-facing backend process, while still allowing the backend to:
- sign Ethereum transactions (ETH transfer / TicketBroker redemption)
- sign Livepeer TicketBroker tickets (EIP-191 “defunct” message signing)
- expose a remote attestation document so operators/clients can verify the key lives inside an approved enclave image

This repo implements the **backend-side plumbing**:
- a remote signer client (`payments/signer.py`)
- wiring in `payments/main.py` to delegate signing when `PAYMENTS_SIGNER_ENDPOINT` is set
- API endpoints to fetch signer status + attestation (`/api/tee/*`)

## Architecture (AWS Nitro Enclaves recommended)

Nitro Enclaves have **no direct networking**, so the common pattern is:

1. **Untrusted parent instance** runs the Payments backend HTTP API (FastAPI).
2. A **trusted enclave app** holds the private key and exposes a small signing RPC over **vsock**.
3. Payments backend sends:
   - `sign_transaction` requests (raw tx dict) and receives `raw_tx`
   - `sign_message_defunct` requests and receives signatures
   - `attestation` requests and receives a signed attestation document

Security note: a TEE protects the key from the host OS, but you still need to decide what *policy* the signer should enforce (e.g., only allow `TicketBroker.batchRedeemWinningTickets` calls, only allow registered recipients, etc.). The first milestone here is **key isolation + attestation**; policy enforcement can be added inside the enclave service next.

## Backend configuration

To use a remote signer (TEE-friendly), set:

- `PAYMENTS_SIGNER_ENDPOINT=vsock://<cid>:<port>` (or `tcp://host:port` for non-TEE testing)
- `PAYMENTS_SIGNER_TIMEOUT_SECONDS=5`
- `PAYMENTS_SIGNER_EXPECTED_ADDRESS=0x...` (optional safety check)

When `PAYMENTS_SIGNER_ENDPOINT` is set, the backend will **ignore**:
- `PAYMENT_PRIVATE_KEY`
- `PAYMENT_KEYSTORE_PATH` / `PAYMENT_KEYSTORE_PASSWORD`

## API endpoints

- `GET /api/tee/status` (viewer token allowed)
  - returns `{ mode: remote|local|none, address, attestation_available }`
- `GET /api/tee/attestation?nonce=0x...` (viewer token allowed)
  - returns `{ address, document_b64, nonce_hex }`

## Remote signer protocol (length-prefixed JSON)

Transport: TCP or vsock. Message framing:

1. 4-byte big-endian length
2. JSON payload bytes

Request format:

```json
{"method":"address","params":{}}
```

Response format:

```json
{"result":{"address":"0x..."}}
```

Supported methods:
- `address` → `{ address }`
- `sign_message_defunct` with `{ message_hash: "0x..." }` → `{ signature: "0x..." }`
- `sign_transaction` with `{ tx: { ... } }` → `{ raw_tx: "0x..." }`
- `attestation` with optional `{ nonce: "0x..." }` → `{ document_b64: "..." }` (if available)
- `provision` (enclave bootstrap only) with KMS ciphertext + AWS session credentials → `{ address: "0x..." }`

## Local (non-TEE) signer demo server

For quick wiring tests (not secure), run:

```bash
export SIGNER_PRIVATE_KEY=0x...
python3 scripts/tee_signer_server.py --listen tcp://127.0.0.1:5000
```

Then point the backend at it with:

```bash
PAYMENTS_SIGNER_ENDPOINT=tcp://127.0.0.1:5000
```

For real TEE attestation, the enclave app must generate a genuine attestation document (AWS NSM) and return it as `document_b64`.

## Docker note (vsock often blocked)

Many Docker installs block `AF_VSOCK` socket creation under the default seccomp profile. If your Payments container
crashes with `PermissionError: [Errno 1] Operation not permitted` when using `PAYMENTS_SIGNER_ENDPOINT=vsock://...`,
run a host-side TCP↔vsock bridge and point Payments at `tcp://...` instead.

Example (host):

```bash
python3 scripts/vsock_tcp_bridge.py --listen-host 172.17.0.1 --listen-port 5001 --vsock-cid <cid>
```

Payments `.env`:

```bash
PAYMENTS_SIGNER_ENDPOINT=tcp://172.17.0.1:5001
```

## Nitro Enclaves runbook

See `docs/nitro-enclave-signer.md` for a practical EC2 build/run flow (KMS-unseal + `vsock-proxy` + provisioning).

## Next: full TEE core

See `docs/tee-core.md` for the roadmap to make the enclave the final authority for ledger + payouts (not just key custody).

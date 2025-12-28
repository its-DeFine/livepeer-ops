# Embody Payments Backend

FastAPI service that tracks orchestrator registrations, balances, and workload credits.

## Run (local)

1. Copy `.env.example` to `.env` and fill in required values.
2. Start the stack:

```bash
docker compose up -d
```

## Deploy (recommended: GHCR image)

This repo publishes a Docker image to GHCR on every `main` push.

1. Set `PAYMENTS_IMAGE` in your `.env` (tag or digest), for example:

```bash
PAYMENTS_IMAGE=ghcr.io/its-define/payments-backend:latest
# or pin a digest:
# PAYMENTS_IMAGE=ghcr.io/its-define/payments-backend@sha256:<digest>
```

2. Pull + restart:

```bash
docker compose pull payments-backend
docker compose up -d
```

## Backups

See `docs/backups.md`.

## Livepeer TicketBroker payouts (experimental)

This backend can pay orchestrators by issuing an *always-winning* Livepeer TicketBroker ticket and redeeming it while paying gas.

- Configure:
  - `PAYMENTS_PAYOUT_STRATEGY=livepeer_ticket`
  - `PAYMENTS_LIVEPEER_TICKET_BROKER_ADDRESS=0xa8bb618b1520e284046f3dfc448851a1ff26e41b` (Arbitrum mainnet proxy)
  - `ETH_RPC_URL=<arbitrum rpc>`
  - `ETH_CHAIN_ID=42161`
  - `PAYMENT_PRIVATE_KEY=<sender key>` (this address must keep its TicketBroker deposit funded)
  - `PAYMENTS_LIVEPEER_DEPOSIT_AUTOFUND=true` (optional; keep deposit topped up)
  - `PAYMENTS_LIVEPEER_DEPOSIT_TARGET_ETH=0.02` (optional; target deposit)
  - `PAYMENTS_LIVEPEER_DEPOSIT_LOW_WATERMARK_ETH=0.01` (optional; only top up when below this)
  - `PAYMENTS_LIVEPEER_BATCH_PAYOUTS=true` and `PAYMENTS_LIVEPEER_BATCH_MAX_TICKETS=20` (optional; batch multiple payouts into one onchain tx)
  - `PAYMENTS_PAYOUT_CONFIRMATIONS=1` and `PAYMENTS_PAYOUT_RECEIPT_TIMEOUT_SECONDS=300` (optional; ledger is cleared only after receipt success)
  - `PAYMENTS_PAYOUTS_PATH=/app/data/payouts.json` (optional; persists pending payouts to avoid double pays across restarts/timeouts)

Demo (single payout):

```bash
python3 scripts/livepeer_ticket_demo.py --recipient 0x... --amount-eth 0.001
```

Demo (batch payout):

```bash
python3 scripts/livepeer_ticket_demo.py --batch-payouts-json payouts.json
```

## Forwarder Health Reports (recommended)

To avoid Payments polling every orchestrator on every cycle, a trusted watcher (typically running on the forwarder) can push periodic health snapshots into the registry:

- Report endpoint (admin token): `POST /api/orchestrators/{orchestrator_id}/health`
- Controls staleness: `PAYMENTS_FORWARDER_HEALTH_TTL_SECONDS` (default `120`)

When a fresh forwarder health snapshot exists, Payments uses it for payment eligibility decisions instead of calling the orchestrator `health_url`.

## Image Licensing (public-but-encrypted images)

This backend can act as a minimal “license/key + lease” service for containers that ship an encrypted payload.

**Admin flow (recommended)**

1. Register an image secret (used to decrypt the payload) and an artifact location (so Payments can presign per lease):

```bash
IMAGE_REF="ghcr.io/its-define/unreal_vtuber/embody-ue-ps:enc-v1"
ARTIFACT_S3_URI="s3://<bucket>/<path>/embody-ue-ps.tar.zst.age"

# secret_b64 is expected to be base64(age-identity-file-bytes)
SECRET_B64="$(python3 - <<'PY'
import base64, pathlib
print(base64.b64encode(pathlib.Path("embody-ue-ps-enc-v1.agekey").read_bytes()).decode("ascii"))
PY
)"

curl -sS -X PUT \
  -H "X-Admin-Token: $PAYMENTS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"image_ref\":\"$IMAGE_REF\",\"secret_b64\":\"$SECRET_B64\",\"artifact_s3_uri\":\"$ARTIFACT_S3_URI\"}" \
  "https://<payments>/api/licenses/images"
```

2. Create a wallet-bound invite code (single-use) and give it to the orchestrator:

```bash
curl -sS -X POST \
  -H "X-Admin-Token: $PAYMENTS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"image_ref\":\"$IMAGE_REF\",\"bound_address\":\"0x1111111111111111111111111111111111111111\",\"ttl_seconds\":604800,\"note\":\"onboarding\"}" \
  "https://<payments>/api/licenses/invites"
```

**Orchestrator runtime flow**

Redeem invite → mint token + grant access:

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"<INVITE_CODE>\",\"orchestrator_id\":\"<orchestrator_id>\",\"address\":\"0x1111111111111111111111111111111111111111\"}" \
  "https://<payments>/api/licenses/invites/redeem"
```

Request a lease + decryption secret:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $ORCH_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"image_ref\":\"$IMAGE_REF\"}" \
  "https://<payments>/api/licenses/lease"
```

The lease response includes:
- `secret_b64` (age identity bytes, base64)
- `artifact_url` (fresh presigned URL per lease when `artifact_s3_uri` is configured and Payments has AWS creds/region)

Then periodically renew:

```bash
curl -sS -X POST -H "Authorization: Bearer $ORCH_TOKEN" \
  "https://<payments>/api/licenses/lease/<lease_id>/heartbeat"
```

Audit log: `data/audit/license.log` (JSONL).

## Session Billing (Pixel Streaming usage)

Edges can report “session connected / heartbeat / disconnected” events to the Payments backend, so orchestrators are credited by **connected session time**.

- Enable on Payments: set `PAYMENTS_SESSION_CREDIT_ETH_PER_MINUTE` (non-zero) and optionally require `PAYMENTS_SESSION_REPORTER_TOKEN`.
- Configure session segmenting (default 40 minutes): `PAYMENTS_SESSION_SEGMENT_SECONDS=2400`.
- Configure each edge `ps-gateway`: set `PAYMENTS_API_URL` and `PAYMENTS_SESSION_TOKEN` (must match `PAYMENTS_SESSION_REPORTER_TOKEN`).
- Reporting endpoint: `POST /api/sessions/events`
- Audit endpoint (viewer/admin token): `GET /api/sessions`
- Ledger entries use `reason="session_time"` with `session_id`, `edge_id`, `segment_index`, `duration_ms`, and `proof_hash` in metadata (credits are emitted on session close or segment rollover).
- Each session event also updates an **activity lease** (`lease_id="session:<session_id>"`) so autosleep watchers can treat sessions and content jobs uniformly via `GET /api/activity/leases?active_only=true`.

## Content Jobs (time-based workloads)

For non-interactive content generation, prefer creating **time-based** workloads so the ledger is fully auditable (no opaque backfills).

- Configure the rate:
  - `PAYMENTS_WORKLOAD_TIME_CREDIT_ETH_PER_MINUTE=0.000005353596` (default aligns with `Embody-Inc/cost-model.md`)
- Create a workload and credit the ledger immediately (admin token):

```bash
curl -sS -X POST \
  -H "X-Admin-Token: $PAYMENTS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "workload_id":"<unique-id>",
    "orchestrator_id":"<orch-id>",
    "duration_ms":180000,
    "plan_id":"<plan-id>",
    "run_id":"<run-id>",
    "artifact_uri":"/path/to/output.webm"
  }' \
  "https://<payments>/api/workloads/time"
```

## Recording Jobs (S3 artifacts)

For API-driven recording workloads (runner → recorder → upload), configure an S3 bucket and use the job endpoint:

- Configure on Payments:
  - `PAYMENTS_RECORDINGS_BUCKET=<bucket>`
  - `PAYMENTS_RECORDINGS_PREFIX=recordings` (default)
  - `PAYMENTS_RECORDINGS_REGION=<optional>`
  - `PAYMENTS_RECORDINGS_PRESIGN_SECONDS=3600` (default)
- Start a job (admin token): `POST /api/jobs/record`
- Get status (viewer/admin token): `GET /api/jobs/{job_id}`
- Get a fresh download URL (viewer/admin token): `GET /api/recordings/presign?s3_uri=s3://...`

## Orchestrator stats (dashboard helpers)

With an orchestrator token (from invite redemption or admin minting), orchestrators can query their own state:

- `GET /api/orchestrators/me`
- `GET /api/orchestrators/me/stats?days=30`

Admins/viewers can query stats for any orchestrator:

- `GET /api/orchestrators/{orchestrator_id}/stats?days=30`

## Ledger reconciliation (report)

To compare the current `balances.json` to the append-only ledger journal (`audit/ledger-events.log`), generate a markdown report:

```bash
python3 scripts/reconcile_ledger.py \
  --data-dir /app/data \
  --label stage \
  --out /app/data/audit/reconcile-report.md \
  --write-reconciled-balances /app/data/balances.reconciled.json \
  --write-mismatches-json /app/data/audit/reconcile-mismatches.json
```

If `workloads.json` exists, the report also includes a section listing verified/paid workloads that have artifacts but were not credited yet.

## Ledger reconciliation (duplicate-hash sweep bug)

If historical content sweeps produced duplicated `artifact_hash` values (and one orchestrator was consistently first in the sweep), you can standardize the **non-unique** workload credits with a single reconciliation adjustment per orchestrator:

```bash
python3 scripts/standardize_duplicate_workload_credits.py \
  --data-dir /app/data \
  --standard-non-unique-eth 0.00224230 \
  --participation-only nico-utp \
  --participation-only orch-local-hoshi \
  --apply
```

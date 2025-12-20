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
- Configure each edge `ps-gateway`: set `PAYMENTS_API_URL` and `PAYMENTS_SESSION_TOKEN` (must match `PAYMENTS_SESSION_REPORTER_TOKEN`).
- Reporting endpoint: `POST /api/sessions/events`
- Audit endpoint (viewer/admin token): `GET /api/sessions`
- Ledger entries use `reason="session_time"` with `session_id`, `edge_id`, and `delta_ms` in metadata.

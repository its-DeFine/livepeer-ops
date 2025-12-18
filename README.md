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

## Image Licensing (public-but-encrypted images)

This backend can act as a minimal “license/key + lease” service for containers that ship an encrypted payload.

**Admin flow**

1. Mint an orchestrator token:

```bash
curl -sS -X POST \
  -H "X-Admin-Token: $PAYMENTS_ADMIN_TOKEN" \
  "https://<payments>/api/licenses/orchestrators/<orchestrator_id>/tokens"
```

2. Register an image secret (used to decrypt the payload):

```bash
curl -sS -X PUT \
  -H "X-Admin-Token: $PAYMENTS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image_ref":"ghcr.io/its-define/unreal_vtuber/embody-ue-ps:enc-v1"}' \
  "https://<payments>/api/licenses/images"
```

3. Allow the orchestrator to access that image:

```bash
curl -sS -X POST \
  -H "X-Admin-Token: $PAYMENTS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orchestrator_id":"<orchestrator_id>","image_ref":"ghcr.io/its-define/unreal_vtuber/embody-ue-ps:enc-v1"}' \
  "https://<payments>/api/licenses/access/grant"
```

**Orchestrator runtime flow**

Request a lease + decryption secret:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $ORCH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image_ref":"ghcr.io/its-define/unreal_vtuber/embody-ue-ps:enc-v1"}' \
  "https://<payments>/api/licenses/lease"
```

Then periodically renew:

```bash
curl -sS -X POST -H "Authorization: Bearer $ORCH_TOKEN" \
  "https://<payments>/api/licenses/lease/<lease_id>/heartbeat"
```

Audit log: `data/audit/license.log` (JSONL).

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

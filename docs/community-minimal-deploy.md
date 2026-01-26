# Minimal Community Deploy

This guide is for operators who want to run the Payments backend as a small, self-hosted API for:

- orchestrator registration metadata (a simple registry)
- a lightweight ledger of credits/balances
- optional payouts (dry-run by default)

It intentionally keeps the stack minimal and leaves optional/advanced modules **disabled by default**.

## What runs in the minimal stack

- `payments-backend` (FastAPI) + a local data directory mounted to `/app/data`

Optional services are available via Docker Compose profiles:

- `ops`: log collection sidecar
- `witness`: TEE checkpoint witness loop

## Requirements

- Docker + Docker Compose (v2)

## Quickstart (single host)

1) Create an environment file:

```bash
cp .env.example .env
```

2) Set at minimum (recommended for any host that is not strictly localhost-only):

- `PAYMENTS_API_ADMIN_TOKEN` (strong random string)
- optionally `PAYMENTS_VIEWER_TOKENS` (comma-separated) for read-only access

3) Start the minimal stack:

```bash
docker compose up -d
```

4) Verify the API is reachable:

```bash
curl -sS http://127.0.0.1:8081/docs >/dev/null
```

Notes:
- The compose file defaults to a published image (`ghcr.io/its-define/payments-backend:latest`). Pin `PAYMENTS_IMAGE` to a tag or digest for reproducible deployments.
- Persistent state lives under `./data` by default (override with `PAYMENTS_DATA_DIR`).

## Enabling optional profiles

Run with the desired profiles:

```bash
docker compose --profile ops up -d
docker compose --profile witness up -d
```

Or set `COMPOSE_PROFILES`:

```bash
COMPOSE_PROFILES=ops,witness docker compose up -d
```

## What’s optional (and stays off by default)

The codebase includes optional modules used in some deployments that you can ignore unless you need them:

- Pixel Streaming session-billing (`/api/sessions/events`) and `/power` gating
- autosleep polling/crediting
- image licensing + “encrypted artifact lease” flows (including S3 presigning)
- TEE signer/core integration and checkpoint witness tooling

Most of these features only activate when corresponding env vars are set (or when the optional compose profiles are enabled).

## Security notes (read before exposing publicly)

- If you expose the API on the public internet, set `PAYMENTS_API_ADMIN_TOKEN` (and ideally `PAYMENTS_VIEWER_TOKENS`) and put the service behind a reverse proxy / firewall.
- Without tokens configured, many endpoints are intentionally open to support simple local/dev usage.

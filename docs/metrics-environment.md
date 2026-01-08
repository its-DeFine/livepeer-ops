# Metrics Environment (DevOps + Stage)

This document describes how to run a **separate** Payments Backend environment dedicated to **Livepeer SLA / synthetic workload verification**, without sharing state/tokens/logs with existing Payments environments.

## Why a separate environment?

- Workload verification has different risk/traffic patterns (high write volume, test artifacts, automated payouts).
- We want isolation for:
  - Admin/viewer tokens
  - TEE state blobs + audit logs
  - Workload records + artifacts
  - On-chain checkpointing configuration

## Environments

- **metrics-devops**: operations-only (checkpoint witness, admin tools, log collection, audits)
- **metrics-stage**: public-ish staging API for synthetic tests + payout trials (ideally on testnet or dry-run)

Decide upfront whether stage uses **Arbitrum mainnet** (real payouts) or a **testnet/dry-run** configuration.

## Docker Compose: env/data separation

`docker-compose.yml` supports parameterized env + data paths:

- `PAYMENTS_ENV_FILE` (default: `.env`)
- `PAYMENTS_DATA_DIR` (default: `./data`)
- `PAYMENTS_PORT` (default: `8081`)

Example (metrics-stage on a host):

```bash
PAYMENTS_ENV_FILE=.env.metrics-stage \
PAYMENTS_DATA_DIR=./data-metrics-stage \
PAYMENTS_PORT=8181 \
docker compose up -d
```

Example (metrics-devops on a host, with witness enabled):

```bash
PAYMENTS_ENV_FILE=.env.metrics-devops \
PAYMENTS_DATA_DIR=./data-metrics-devops \
PAYMENTS_PORT=8281 \
docker compose --profile witness up -d
```

Notes:
- `container_name:` values in compose are fixed; run **one environment per host** (recommended) unless you remove/parameterize container names.

## Required config (non-secret guidance)

Create `.env.metrics-stage` / `.env.metrics-devops` by copying `.env.example` and setting at minimum:

- **Tokens**
  - `PAYMENTS_API_ADMIN_TOKEN` (unique per env)
  - `PAYMENTS_VIEWER_TOKENS` (unique per env; if used)
- **Chain**
  - `ETH_RPC_URL`, `ETH_CHAIN_ID`
  - If checkpoint witness runs: `CHECKPOINT_RPC_URL`, `CHECKPOINT_CONTRACT_ADDRESS`, `CHECKPOINT_CHAIN_ID`
- **Workload payouts**
  - `PAYMENTS_WORKLOAD_TIME_CREDIT_ETH_PER_MINUTE` (or pay per-workload via `/api/workloads`)
  - `PAYMENTS_WORKLOAD_ARCHIVE_BASE` (artifact directory; default `/app/recordings`)

## TEE separation (when using Nitro Enclaves)

If you run the TEE signer/core in Nitro:
- Use a **separate KMS key** per environment.
- Maintain a **separate PCR allowlist** per environment.

Do not reuse prod attestation policies for metrics-stage.


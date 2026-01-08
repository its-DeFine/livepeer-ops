# Session Billing (Pixel Streaming)

This backend can credit orchestrators based on **connected Pixel Streaming session time**.

## Overview

- Each edge (`ps-gateway`) reports WebSocket lifecycle events to Payments:
  - `start` (WS connected)
  - `heartbeat` (periodic while connected)
  - `end` (WS disconnected)
- Payments stores session state in `sessions.json` and credits the orchestrator ledger with `reason="session_time"` using the elapsed time since the last billed event (`delta_ms`).

Orchestrator attribution is done by matching `upstream_addr` (the game host IP) to the registry record field `host_public_ip`.

## Enable

Set (via env or `.env`):

- `PAYMENTS_SESSION_CREDIT_ETH_PER_MINUTE` (set to a non-zero value to enable)
- `PAYMENTS_SESSION_REPORTER_TOKEN` (optional; if set, edges must send it)
- `PAYMENTS_SESSIONS_PATH` (optional; defaults to `/app/data/sessions.json`)

On each edge `ps-gateway`, set:

- `PAYMENTS_API_URL=http://<payments-ip>:8081`
- `PAYMENTS_SESSION_TOKEN=<same-as-PAYMENTS_SESSION_REPORTER_TOKEN>` (if required)
- `PAYMENTS_SESSION_HEARTBEAT_SECONDS=15` (optional)

## Test (manual)

Send a session event (replace values):

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "X-Session-Token: <PAYMENTS_SESSION_REPORTER_TOKEN>" \
  -d '{"session_id":"test-1","upstream_addr":"203.0.113.10","upstream_port":8888,"edge_id":"edge-a","event":"start"}' \
  "http://<payments-ip>:8081/api/sessions/events"
```

List sessions (viewer/admin token required if configured):

```bash
curl -sS -H "X-Admin-Token: <token>" "http://<payments-ip>:8081/api/sessions?limit=50"
```

## Audit

- Session records: `sessions.json` (path: `PAYMENTS_SESSIONS_PATH`)
- Ledger journal: `PAYMENTS_LEDGER_JOURNAL_PATH` (look for `reason="session_time"`)

## Power-state metering (optional)

If you want to pay only while an orchestrator is **powered on**, enable the power-meter loop:

- `PAYMENTS_POWER_METER_ENABLED=true`
- `PAYMENTS_POWER_CREDIT_ETH_PER_MINUTE=<rate>`
- `PAYMENTS_POWER_POLL_SECONDS=60` (poll cadence)
- `PAYMENTS_POWER_MAX_GAP_SECONDS=180` (skip credit if poll gaps are too large)

This mode credits the ledger with `reason="power_time"` when `/power` reports `state=awake`.
It is intentionally conservative: if the poll loop misses a window or `state` is unknown, it skips credit.
Set `PAYMENTS_SESSION_CREDIT_ETH_PER_MINUTE=0` if you want **power-only** payments.

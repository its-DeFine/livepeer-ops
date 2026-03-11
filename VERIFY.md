# Verification Contract

This file is the canonical command matrix for `livepeer-ops`.

## Assumptions

- Run commands from the repo root unless the command explicitly changes directories.
- Use a disposable local Python environment for local-safe checks. Example:

```bash
python3 -m venv /tmp/livepeer-ops-harness-venv
source /tmp/livepeer-ops-harness-venv/bin/activate
pip install -r requirements.txt pytest
```

- Keep throwaway env files and runtime data outside the repo when a stack check needs them.

## Evidence Location

Store verification evidence under:

`logs/harness/<YYYY-MM-DD>/<change-id>/`

Recommended layout:

- `logs/harness/<date>/<change-id>/local/` for `local-safe` checks
- `logs/harness/<date>/<change-id>/runtime/` for `runtime-required` checks
- `logs/harness/<date>/<change-id>/notes.md` for short proof-of-done notes

`logs/` is already gitignored, so machine-generated evidence can stay local.

## Proof Rules

- Docs-only change:
  - proof is the doc diff plus the command matrix staying grounded in real repo commands
  - use deterministic doc checks first:
    - `rg -n 'Harness Entry|WORKFLOW.md|VERIFY.md|docs/harness-baseline.md' README.md`
    - `rg -n 'Docs-only change|git diff -- README.md VERIFY.md|rg -n' VERIFY.md`
    - `git diff -- README.md VERIFY.md`
  - when the diff itself makes the change obvious, `logs/harness/...` is optional rather than required
- `local-safe` change:
  - proof is the relevant command output captured under `local/` when needed
- `runtime-required` change:
  - proof is the local-safe check plus stack or HTTP output under `runtime/`
- `operator-only` action:
  - do not run by default
  - require an explicit operator ask plus redacted evidence

## Local-Safe Commands

Use these first when the touched surface matches.

| Surface | Command | What it proves |
| --- | --- | --- |
| Python file surface | `python -m compileall payments scripts ops tests` | The touched Python files still parse |
| Ledger and processor logic | `python -m pytest tests/test_ledger.py tests/test_processor.py` | Local balance and processor behavior still passes |
| Split-surface config and routing | `python -m pytest tests/test_config_split_surfaces.py tests/test_api_split_surface_gating.py` | Host split enforcement and route gating stay intact |
| Core API auth and registry surface | `python -m pytest tests/test_api.py -k 'register_endpoint_success or admin_listing_requires_token or admin_listing_redacts_ips_for_unlisted_clients'` | Registration, admin auth, and IP redaction behavior still passes |

## Runtime-Required Commands

These checks mutate local runtime state or require a prepared disposable env file, so they are not the default first step.

| Command | Scope | Notes |
| --- | --- | --- |
| `PAYMENTS_ENV_FILE=/tmp/livepeer-ops.env PAYMENTS_DATA_DIR=/tmp/livepeer-ops-data PAYMENTS_PORT=18081 docker compose up -d payments-minio payments-backend` | Local stack bring-up | Prepare `/tmp/livepeer-ops.env` from `.env.example` outside the repo; do not write repo `.env*` files for harness work |
| `curl -fsS http://127.0.0.1:18081/docs >/dev/null` | Local HTTP docs/health surface | Confirms the API is serving once the stack is up |
| `docker compose ps payments-minio payments-backend` | Local container status | Confirms the main runtime services are actually up |

## Operator-Only Commands

Do not treat these as default agent actions.

| Command or surface | Why it is restricted |
| --- | --- |
| `python3 ops/deploy_payments_backend_ssh.py ...` | Reaches remote hosts and mutates live env or container state |
| `./scripts/onboard_livepeer_ticketbroker.sh` | Touches payout and TicketBroker setup flow |
| `python3 scripts/livepeer_ticket_demo.py ...` | Exercises on-chain payout behavior |
| `python3 scripts/provision_enclave_signer.py ...` | Provisions enclave or KMS-backed signer state |
| `python3 scripts/publish_tee_core_checkpoint.py --watch ...` | Publishes live transparency checkpoints |
| Admin POSTs to live registry, payout, or `/ops/*` surfaces | Mutate live backend or orchestrator-facing state |

## Stop Conditions

Stop instead of improvising when:

- the required command is `runtime-required` and no disposable env or operator context is available
- the only available path needs `.env*`, secrets, tokens, or live host mutations that the issue did not authorize
- the check would validate product or infra behavior outside the allowed harness wedge
- the evidence cannot be captured in a deterministic way

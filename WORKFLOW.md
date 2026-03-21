# Livepeer Ops Workflow

This file is the repo-owned execution contract for agents working in `livepeer-ops`.

## Read Order

Read these in order before making a non-trivial change:

1. `AGENTS.md`
2. `README.md`
3. `docs/overview.md`
4. `WORKFLOW.md`
5. `VERIFY.md`
6. `docs/harness-baseline.md`

Then inspect the exact code or doc surface you plan to touch. Common first stops:

- `docker-compose.yml`
- `payments/api.py`
- `payments/config.py`
- `payments/main.py`
- `tests/test_api.py`
- `tests/test_config_split_surfaces.py`
- `tests/test_api_split_surface_gating.py`

## Repo Contract

- Main operator docs:
  - `README.md`
  - `docs/overview.md`
  - `docs/community-minimal-deploy.md`
- Main runtime entrypoint: `docker-compose.yml`
- Local app entrypoint: `python -m payments.main`
- Best local-safe verification surfaces:
  - `tests/test_ledger.py`
  - `tests/test_processor.py`
  - `tests/test_config_split_surfaces.py`
  - `tests/test_api_split_surface_gating.py`
  - `tests/test_api.py`
- Runtime-required surfaces:
  - local stack bring-up through Docker Compose
  - local HTTP health/docs checks
  - MinIO-backed licensing flows
- Operator-only surfaces:
  - `ops/deploy_payments_backend_ssh.py`
  - payout and TicketBroker scripts
  - enclave provisioning, signer, and checkpoint publication scripts
- Repo boundary:
  - Unreal runtime implementation, Pixel Streaming behavior, and cross-repo orchestration policy live outside this repo

## Default Execution Loop

1. Name the exact path, endpoint, or command you are changing.
2. Pick the smallest wedge that satisfies the issue.
3. Choose the closest verification command from `VERIFY.md` before editing.
4. Make the smallest reversible change that can satisfy that check.
5. Capture proof in the evidence path defined in `VERIFY.md` when command output matters.
6. Stop when the requested acceptance check is met. Do not expand into adjacent backend or infra work.

## Proof Of Done

Use the proof rule that matches the change type:

- Docs-only change:
  - updated docs define the right read order, repo boundary, and verification classes
  - file diff is the main artifact
- Local-safe change:
  - run the closest local-safe command for the touched subsystem
  - store command output under `logs/harness/...` when the result is not obvious from stdout
- Runtime-required change:
  - complete the closest local-safe check first
  - then collect stack or HTTP evidence under `logs/harness/.../runtime/`
- Operator-only action:
  - do not run by default
  - require an explicit operator ask plus redacted evidence

## Stop Conditions

Stop and ask for a narrower packet if any of these become necessary:

- modifying `.github/**`, `.env*`, secrets, tokens, allowlists, or live infra state
- changing payout, billing, credits, registration, or other backend feature behavior when the issue is harness-only
- relying on a runtime-only check when no disposable local env or operator context is available
- widening from one bounded repo task into Unreal_Vtuber work or cross-repo orchestration
- opening implementation PR flow without a real tracker key (Linear task key or GitHub issue number)

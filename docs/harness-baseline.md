# Harness Baseline

This doc defines the minimum repo-owned harness surface for `livepeer-ops`.

## Correct Entry Path

Read these in order before non-trivial work:

1. `AGENTS.md`
2. `README.md`
3. `docs/overview.md`
4. `WORKFLOW.md`
5. `VERIFY.md`
6. `docs/harness-baseline.md`

Then open only the code and docs that match the issue scope.

## Repo Boundary

This repo owns:

- FastAPI backend surfaces under `payments/`
- local/runtime stack definition in `docker-compose.yml`
- backend tests under `tests/`
- operator helpers under `ops/` and `scripts/`

This repo does not own:

- Unreal avatar runtime implementation
- Pixel Streaming client/runtime behavior outside the backend contract
- control-plane routing or multi-repo orchestration policy

## Existing Operator Entrypoints

- `README.md`: top-level backend and deploy overview
- `docs/overview.md`: one-page architecture summary
- `docs/community-minimal-deploy.md`: single-host bring-up path
- `docker-compose.yml`: main runtime stack entrypoint
- `payments/main.py`: local API process entrypoint
- `ops/deploy_payments_backend_ssh.py`: remote deploy path
- `scripts/`: task-specific helpers for reconciliation, payouts, and enclave flows

## Proof-Of-Done Expectations

- Docs-only: diff clearly improves read order, repo boundary, and verification routing
- `local-safe`: run the nearest local-safe command from `VERIFY.md`
- `runtime-required`: pass a local-safe check first, then collect local stack or HTTP evidence
- `operator-only`: require an explicit human ask and redacted evidence

## Current Harness Posture

- Product and operator documentation already exist.
- Repo-owned harness routing was missing before `WORKFLOW.md` and `VERIFY.md`.
- Future harness work here should stay parked behind the primary `Unreal_Vtuber` wedge unless a new issue explicitly makes this repo active.

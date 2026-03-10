# Agent Notes

This repo uses GitHub Issues as the unit of work and PRs as the execution artifact.

## Harness Entry

Read these in order before making a non-trivial change:

1. `AGENTS.md`
2. `README.md`
3. `docs/overview.md`
4. `WORKFLOW.md`
5. `VERIFY.md`
6. `docs/harness-baseline.md`

Then inspect only the code and docs for the surface you will touch.

## Repo Boundary

- This repo owns the Livepeer ops backend: orchestrator registration, workload/session metering, credits ledger, optional payouts, and optional fleet ops APIs.
- This repo does not own Unreal runtime implementation, Pixel Streaming client behavior, or cross-repo orchestration policy.
- Harness work here is documentation-first. Do not treat a harness pass as permission to widen into backend features or infra changes.

## Evidence Rule

- Use `VERIFY.md` to classify checks as `local-safe`, `runtime-required`, or `operator-only`.
- When command output matters, store it under `logs/harness/<YYYY-MM-DD>/<change-id>/`.
- If no issue number is supplied, stop before opening a new implementation wedge or PR artifact.

## Non-negotiables

- Only do what the Issue asks. If `outcome`, `scope`, `acceptance criteria`, or `allowed/forbidden areas` are missing or unclear, stop and ask for clarification (do not guess).
- Never commit directly to the default branch (`main`/`master`). Work on a branch named `agent/issue-<number>` and open a **draft PR**.
- Keep changes small and surgical; avoid drive-by refactors.
- Do not add or modify secrets/keys/tokens. If an Issue requires secret changes, stop and ask a human.

## Safety / forbidden by default

Unless an Issue explicitly allows it, do not modify:

- `.github/**`
- `*.env*`
- `*.pem`
- `*.key`
- `*secret*`
- `*credentials*`

If the Issue provides its own allowed/forbidden paths, those take precedence.

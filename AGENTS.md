# Agent Notes

This repo uses Linear tasks as the internal unit of work and PRs as the execution artifact. GitHub issues are optional external/public intake, not a prerequisite for internal repo work.

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
- If no Linear task key is supplied, stop before opening a new implementation wedge or PR artifact.

## Non-negotiables

- Only do what the task asks. If `outcome`, `scope`, `acceptance criteria`, or `allowed/forbidden areas` are missing or unclear, stop and ask for clarification (do not guess).
- If no real Linear task key is supplied, stop before opening an implementation branch or PR. Never use placeholder keys such as `<linear-key>`.
- Never commit directly to the default branch (`main`/`master`). Work on a branch named `codex/<linear_key>-<slug>` and open a **draft PR**.
- The PR body must include `Linear: <linear_key>`.
- Keep changes small and surgical; avoid drive-by refactors.
- Do not add or modify secrets/keys/tokens. If a task requires secret changes, stop and ask a human.

## Safety / forbidden by default

Unless a task explicitly allows it, do not modify:

- `.github/**`
- `*.env*`
- `*.pem`
- `*.key`
- `*secret*`
- `*credentials*`

If the task provides its own allowed/forbidden paths, those take precedence.

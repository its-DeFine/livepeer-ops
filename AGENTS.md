# Agent Notes

This repo uses GitHub Issues as the unit of work and PRs as the execution artifact.

## Non-negotiables

- Only do what the Issue asks. If `outcome`, `scope`, `acceptance criteria`, or `allowed/forbidden areas` are missing or unclear, stop and ask for clarification (do not guess).
- Stop before implementation if no real GitHub issue number is supplied, or if a placeholder such as `issue-0` is being used.
- Never commit directly to the default branch (`main`/`master`). Work on a branch named `codex/issue-<number>-<slug>` and open a **draft PR**.
- The draft PR body must link the real issue with `Closes #<number>` or `Refs #<number>`.
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

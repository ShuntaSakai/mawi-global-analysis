# Development Workflow

## Working tree and branches

Work directly in the currently checked-out `main` working tree unless the human
explicitly requests a different workflow. Verify the active branch before
editing. Do not create branches or worktrees, or switch branches, for routine
work.

Preserve all existing human changes. Never stash, reset, restore, checkout,
overwrite, or discard unrelated changes.

## Human-owned Git history

The human decides what enters history and what is published. Unless explicitly
asked, do not run `git add`, commit, amend, merge, rebase, push, create tags,
or open pull requests. Leave completed work uncommitted in `main` for human
inspection.

## Implementation and review

Before changing research behavior, read the research contract, the relevant
experiment config, and the affected implementation and tests. Follow the
repository's established test-first practice for code behavior changes.

Treat changes to research semantics, experiment comparability, cache identity,
provenance, or artifact boundaries as research/design changes. Do not present
them as ordinary refactors or make them implicitly. Routine refactors must
preserve the relevant documented and tested contracts.

Run verification proportionate to the change, inspect the result, and review
the final diff for contract compliance and code quality. Record failures and
deferred checks accurately. Fixture and golden validation are not evidence of a
successful real-data end-to-end run.

## Completion report

Report:

1. Files added, modified, and deleted.
2. Verification commands and their results.
3. Known deviations, deferred checks, or remaining issues.
4. One concise suggested commit message.

Do not create the suggested commit unless the human explicitly asks.

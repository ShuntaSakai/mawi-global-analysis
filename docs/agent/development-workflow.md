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

## Agent usage and token budget

Accuracy takes priority over minimizing token usage, but avoid unnecessary
agent fan-out and repeated repository exploration.

Use subagents selectively when they materially improve implementation
correctness or review quality.

For substantial implementation tasks:

- Prefer one implementer context for one coherent task or phase.
- After implementation and focused tests pass, use one fresh reviewer when
  an independent review would materially reduce risk.
- The reviewer should inspect the changed behavior for the concerns relevant
  to the task, including where applicable:
  - research-contract compliance,
  - artifact and provenance boundaries,
  - algorithm and data-processing correctness,
  - boundary and failure-case semantics,
  - regression risk.
- Fix material reviewer findings before reporting completion.

Avoid unnecessary agent fan-out:

- Do not dispatch multiple agents to implement the same task in parallel
  unless the human explicitly requests comparative implementations.
- Do not use subagents for trivial documentation-only edits or mechanical
  changes where an independent context adds little value.
- Do not make every subagent recursively explore the repository.
- Each agent should read the minimum authoritative and task-relevant files
  needed for its role.
- Reuse an approved design or implementation plan instead of having each
  agent independently redesign the task.

For large features, prefer a small number of coherent phases over many tiny
agent tasks. Each phase should have a testable deliverable and a clear
interface to the next phase.

Token efficiency must not be achieved by skipping tests, provenance checks,
research-contract checks, or independent review when those checks materially
affect research correctness.

## Completion report

Report:

1. Files added, modified, and deleted.
2. Verification commands and their results.
3. Known deviations, deferred checks, or remaining issues.
4. One concise suggested commit message.

Do not create the suggested commit unless the human explicitly asks.

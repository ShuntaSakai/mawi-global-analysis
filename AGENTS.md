# AGENTS.md

This is the entry point for AI agents working in `mawi-global-analysis`.

## Reading order

Before changing the repository, read in this order:

1. This file.
2. [AI documentation index](docs/agent/README.md).
3. The task-relevant documents linked from that index.
4. The relevant code and tests.

`docs/agent/research-contract.md` defines the current repository-wide research
semantics. Experiment configuration files define the settings of a particular
experiment. Use both when a change can affect analysis behavior.

Historical material under `docs/archive/society-2026/superpowers/` and other
existing documents may help explain why older code exists, but it is background
material. It is not a current specification and must not override the AI
documentation, current configuration, code, or tests.

## Repository-wide rules

- Work in the currently checked-out `main` working tree unless the human
  explicitly requests another workflow.
- Before editing, verify that the active branch is `main`.
- Do not create or switch branches, or create Git worktrees, unless explicitly
  requested by the human.
- Preserve existing human changes. Do not stash, reset, restore, checkout,
  overwrite, or discard unrelated work.
- The human owns Git history. Unless explicitly requested, do not run `git
  add`, commit, amend, merge, rebase, push, tag, or open a pull request.
- Leave completed changes uncommitted for human review.
- Run verification appropriate to the change. Do not describe fixture or
  golden validation as real-data validation.
- Treat a change to research semantics, experiment comparability, cache
  identity, or provenance as a research/design change, not a routine refactor.

## Completion report

At the end of a repository change, report the files added, modified, and
deleted; verification commands and results; and known deviations or remaining
issues. Always end with exactly one suggested commit-message line:

`Suggested commit message: <message>`

Do not create the commit unless the human asks.

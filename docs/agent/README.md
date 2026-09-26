# AI Documentation

This directory is the maintained entry point for AI agents after they read the
repository-root [AGENTS.md](../../AGENTS.md).

## Reading guide

Read [research-contract.md](research-contract.md) before changing analysis
semantics, flow/prefix/scan behavior, artifact boundaries, caching, or
provenance. It is the current repository-wide contract for those concerns.

Read [repository-architecture.md](repository-architecture.md) before changing
pipeline boundaries, artifact locations, command-line orchestration, or
notebooks.

Read [development-workflow.md](development-workflow.md) before any repository
change. It defines the required working-tree, Git, review, and completion
practices.

Read [current-state.md](current-state.md) when selecting an experiment,
running existing notebooks, assessing what has been verified, or planning
follow-up work. It is a maintained factual snapshot, not a source of
scientific conclusions.

For a concrete experiment, also read its file in `configs/`, then the relevant
implementation and tests. Existing documents outside `docs/agent/`, including
historical designs and plans in `docs/superpowers/`, are background only unless
a current task explicitly asks for historical context.

## Authority and scope

The research contract is the current repository-wide semantic authority.
Experiment configs provide the current settings for named experiments. Code and
tests establish the implemented behavior and verification evidence. If these
disagree, do not silently choose one: identify the discrepancy and ask for a
research/design decision when it changes semantics.

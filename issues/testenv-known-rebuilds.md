# Adding a test env var rebuilds the whole workspace
> Summary: `osis_base::testenv::KNOWN` is a const list in osis-base, so naming a new `OSIS_*` test variable recompiles every crate in every worktree that picks it up (eph-21054: tier 1 + clippy 556 s, the build alone 3 min 19 s). Low.
> Tags: tests, base

Fix direction: keep the list in a file read at run time (e.g. `core/base/testenv-known.txt` via `include_str!` still rebuilds; a runtime read from the workspace root does not), still checked by tools/policy.py.

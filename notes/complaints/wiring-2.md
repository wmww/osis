# wiring-2
- `tools/claim wiring-1` failed for minutes while the previous worker's `wt release` ran its marking build (cargo test --no-run, build, clippy): the claim's message said so; retrying after it finished worked.
- Test worker threads had no name, so the shadow's per-test reading saw `?` for every property world; `testenv::spawn_named` now names them after their test.
- A new measure env var must be registered in core/base/testenv-known.txt or every test panics at start (OSIS_PROBE_* is exempt): cost one confusing rerun.
- Rebasing a three-commit branch onto main's direct-mark landing conflicted in every commit (role_paths.rs, the README): squashing the branch to one commit first (reset --soft to the merge-base, a local commit) made it one resolution.
- The heavy lock waited about 15 minutes behind another run; a `sh -c` hold builds when the lock frees, so no code edits were possible meanwhile (notes only).
- `tools/heavy sh -c "set -o pipefail; ..."` ran nothing: `sh` is dash, which refuses pipefail, so the hold (taken after a ~10 min wait) ended at once. Use `bash -c` inside a hold.

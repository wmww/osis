# storage-bound-375
- An ad-hoc probe env var named `OSIS_*` makes sim-sweep exit 101 with no message once stderr is piped through grep/tail (testenv refuses unknown `OSIS_*` names); use a non-`OSIS_` name for throwaway probes.
- `sim-sweep` with `--seeds 300` uses every core; easy to forget `tools/heavy` for a "single-scenario" sweep.
- Review: main moved twice during the review; `git checkout --detach main` in the worktree (wip committed) is the cheap way to compare a seed on main, but the next `cargo run` rebuilds the sim either way.

# oracle-dice
- The task's issue (work-sets-parted-link-race) lived only on branch periodic-d, not on main: read it with `git show`.
- `sim.dice` shared by all purposes made a two-run diff useless: fixed. `report.digest` was one hash with no way to see what parted: `Report::parts` names them now.
- A background `cargo test` run moved to the background by the harness at 180 s while I expected the foreground result: run oracles with `run_in_background` from the start.
- The oracle's digest had carried blob IDs, so it could never have tolerated a pass order change; a null run (same mode, another random stream) settles at once whether a difference is luck: `compared_runs_ignore_the_random_stream`. Do this first next time.
- A rebase in the middle brought idle-pass and eph-unify: 100-seed runs on the pre-rebase build said little about the rebased one.

# ephemeral_reverts_with_restarts_alike: a writer and its admin read a thing apart at the end
> Summary: `ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` seed 606027154010 fails on main (cac3fe634) and on again-stand alike: after the run both nodes list a thing in the same groups but the admin reads `Some("15")` on its ephemeral `STATE` where the writer reads none. Listed in tools/known_failures.txt.
> Priority: normal
> Tags: tests, node

- Replay: `OSIS_EPH_START=606027154010 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` (about 2 s).
- The run writes, creates and reverts ephemeral state at random with node and host restarts while the admin demotes the writer to read on one or both groups (`revert_run_with`). Undiagnosed: either an ephemeral write or revert reached one node and not the other, or a restart lost one.

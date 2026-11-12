# Churn seed 657238290944: one node's map lacks another author's key
> Summary: `random_churn_converges_large` seed 657238290944 (from a 1500-seed run at 657238289959) does not converge on main 00e7d7b45: node 2 reads the map without key `vCD6y3SNz1b4ezK2ZMyd` (`v35`, node 3's write) that nodes 0, 1 and 3 have. Cause not traced; not the dead-entry tombstone (fixed in c49f44ace, its reproducer `ephemeral::invalid_part_tombstoned_then_valid_fetched_spec_permissions_6` passes).
> Priority: normal
> Tags: ephemeral, sync, tests

Replay: `OSIS_EPH_START=657238290944 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large` (a few seconds). Held only at node 2: one commit; held only at node 0: another. A lost write at one reader until shown otherwise. Seeds 657238290360 and 657238291250 failed alike in the same run on main b1df40715 and pass on 00e7d7b45.

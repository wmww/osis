# Churn seed 807204137843: two nodes settle on different reads
> Summary: `random_churn_converges_large` seed 807204137843 ends quiescent with node 1 missing a map entry (`bnYN-IM-Evyq6QGLyL4i: v30`) that nodes 0, 2 and 3 read; node 1 holds three commits node 0 lacks and node 0 one that node 1 lacks. A convergence failure in ephemeral sync, not yet studied.
> Priority: normal
> Tags: ephemeral, sync, tests

Replay (deterministic, about 30 s): `OSIS_EPH_START=807204137843 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large`. Found by a gate run of a GUI-only branch (no core change), so it is on main.

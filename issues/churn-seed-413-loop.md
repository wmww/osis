# Churn seed 807204137413 never settles
> Summary: `random_churn_converges_large` seed 807204137413 fails on main with "no quiescence after 2000 rounds (26174 messages): a loop". Not studied yet.
> Priority: normal
> Tags: ephemeral, sync, tests

Replay (about 2 s): `OSIS_EPH_START=807204137413 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large`. Found in a 2000-seed run from 807204137000 on main (bddcd6587). `OSIS_SYNC_TRACE=1` prints the messages; find which entry is placed and deleted over and over.

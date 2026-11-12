# Churn seed 501814946361: no quiescence
> Summary: `random_churn_converges_large` seed 501814946361 never quiesces ("no quiescence after 2000 rounds (10541 messages): a loop"), at small size and `OSIS_FULL=1`; fails on main 963153652 alike. Cause not traced.
> Priority: normal
> Tags: ephemeral, sync, tests

Replay: `OSIS_EPH_START=501814946361 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large` (about 16 s). Some message repeats forever between nodes and hosts; issues/refused-upload-retried.md (a refused upload resent every pass) is one candidate, unconfirmed.

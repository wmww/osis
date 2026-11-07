# Churn seeds 103, 144: a cursor state differs from its rebuild
> Summary: `random_churn_converges_large` at `OSIS_FULL=1` fails the debug rebuild check on `win:cursor.0~` (the state lacks a write a rebuild from held bodies has): seeds 103 and 144. Cause not traced.
> Priority: normal
> Tags: ephemeral, engine, tests

`apply::atomic::check_rebuilt` panics: the rebuild holds an entry (a `v14` write under a session dot, its reset stamp by another session) the state does not. Replay: `OSIS_EPH_START=103 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large` (under a second). The tier-1 run (4 seeds) and the plain-size range pass.

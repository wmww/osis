# Churn seed 913562400022 never settles
> Summary: `random_churn_converges_large` seed 913562400022 ends "no quiescence after 2000 rounds: a loop", with and without the churn-413 fix (held-again commits judged by the join): one node places a fresh encryption of an entry, two others delete it, every round. Not studied.
> Priority: normal
> Tags: ephemeral, sync, tests

- Replay (about 15 s): `OSIS_EPH_START=913562400022 OSIS_EPH_SEEDS=1 cargo test -p osis-node --test it -- --ignored --exact ephemeral::random_churn_converges_large`. Found in a 400-seed run from 913562400000 (1 of 400).
- `OSIS_SYNC_TRACE=1`: node 0 streams `Deleted(dcfc..)` plus `Added` of a new blob under label 271da..; nodes 1 and 3 send `Delete` for it. Making `carrier_of` skip the forgotten record of a held commit does not end it.
- Start at: which rule places (`body_sends`/`encrypt_again`) and which deletes (`judge`/`judge_forgotten`/`carried`) for that commit; whether it is a memory commit and whether its deleters hold it.

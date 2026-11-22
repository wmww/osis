# A sync differential seed: a caught-up reader lacks must-hold bodies
> Summary: osis-sync `differential::histories_hold_their_closure_plain` fails at `OSIS_SYNC_START=285299238820`: "must-hold bodies a caught-up reader lacks at quiet" (holder 1, reader 0), on main's binary (91d5ba5f9) as on the test-cost-4 branch. Not shrunk, cause not read.
> Priority: normal
> Tags: sync, tests

Replay: `OSIS_SYNC_START=285299238820 OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`. Shrink with `OSIS_SHRINK_MATCH` set, in a full `tools/heavy` hold.

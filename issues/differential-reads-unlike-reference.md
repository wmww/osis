# Differential: a node reads a thing unlike the reference
> Summary: Sync differential `histories_hold_their_closure_plain` seed 149236181493 fails on main: "node 1 reads thing 0 unlike the reference", or, on later main, "node 2, removed from its account, reads thing 0: Some(Str(\"v1\"))" (a removed node still reading). Not yet shrunk or diagnosed.
> Priority: normal
> Tags: sync, tests

Replay: `OSIS_SYNC_START=149236181493 OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain` (panics at `core/sync/tests/it/harness/history.rs:1161`). Shrink with `OSIS_SYNC_SHRINK=1`.

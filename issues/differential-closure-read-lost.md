# Sync differential: a node ends without reading a thing the model reads
> Summary: osis-sync `differential::histories_hold_their_closure_plain` fails on some seeds on main at 89ae22eb4: "node 0 reads thing 1: None, the model reads it", the node holding a write role on the thing through its account and an accepted ticket, but no secrets of the account the thing's secrets derive from. Not shrunk yet.
> Priority: normal
> Tags: sync, engine, tests

Replay: `OSIS_SYNC_START=157455058984 OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain` (seed numbers move whenever commit bytes change: shrink to a script, then a seed-0 hand test). The panic's why-role dump: role Some(Write) by a direct account path, ticket accepted, `secrets derive from` an account whose role is None, `lost access: not due: no secrets of it held`, node closure `reads false, content held false`. May share a cause with issues/differential-full-size-classes.md.

# Sync differential fails at the gate's size on some seeds
> Summary: `differential::histories_hold_their_closure_plain` at small size fails on fresh offsets: a new node's card failing with a crashed store (seed 219566677909, not shrunk).
> Priority: normal
> Tags: sync, engine, tests

**Seen**: seed 219566677909 fails on main. Replay: `OSIS_SYNC_START=<seed> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; scripts replay in a scratch test (notes/sync-test-harness.md, Replaying a script). Shrink with `OSIS_SHRINK_MATCH` set to the class's message (unset, shrinking drifts to another class).

## A new node's card fails on a crashed store
- Seed 219566677909 (fails on main 489976f8b): `the new node's card: Store(Backend(Crashed))` in the harness's `pair` (core/sync/tests/it/harness/mod.rs): node `i` ingesting the new node's card unwraps a store error, likely while an injected crash holds node `i`'s store. Not shrunk; first decide whether `pair` may pick a node whose store is crashed.

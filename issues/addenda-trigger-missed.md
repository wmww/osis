# The order harness finds an addenda trigger missed
> Summary: osis-engine `order::held_set_decides_plain` and `_exhaustive` fail on some seeds (seed 308989299847, the Addenda kind): the engine's end-of-transaction check finds a removal not due that owes addenda (`an addenda trigger missed`). Fails on main's binary (970e0b36d). Lead: role-write vouches' removal reshaped engine `flows/addenda.rs` (`write_owed` one pass; gather and owed folded), landed e10cf80aa.
> Priority: normal
> Tags: engine, tests

Replay: `OSIS_ORDER_SEED=308989299847 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`OSIS_ORDER_LEN=40` for `_exhaustive`; `OSIS_ORDER_SHRINK=1` shrinks it). Panic at `core/engine/src/engine/mod.rs` (the missed-trigger check): `removal CommitId(c5c0f2adccd0a4b0..), not due, owes addenda on [Tid(JIPHoIYe2Ck9wvWdPA2b)]`.

First check whether it fails before e10cf80aa (`tools/bin-at`): if not, the prune dropped a trigger addenda need (a wake the vouch flow raised that addenda relied on, or the single pass of `write_owed` missing a removal made due by an earlier write in the pass). Then a seed-free hand test of the shrunk history.

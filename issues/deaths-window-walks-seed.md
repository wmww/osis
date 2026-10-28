# A deaths window disagrees with the whole replay (walks seed 7204)
> Summary: The debug check after a windowed deaths replay (`retention/deaths.rs` `window`) fails on a `/t/gonemap` body in the walks oracle at seed 7204: the window keeps its last death at its first, a whole replay dates it later. Found on main by the engine-simplify branch's walks run; not investigated.
> Tags: retention, tests

Repro: `OSIS_WALKS_START=7204 OSIS_WALKS_SEEDS=1 cargo test --workspace --test it walks::open_equals_rebuild_random_histories -- --exact` (a run of one seed also trips the test's coverage assertion at the end; the deaths panic comes first). Seeds 7100-7499 otherwise pass.

```
window deaths of CommitId(333b0a0281ec0c42..) on Tid(SyjjLght_HGN8uryhm98) Ak("/t/gonemap"):
Some((Ts(111411356414115840), Ts(111411356414115840))), a whole replay Some((Ts(111411356414115840), Ts(111411356414509056)))
```

`/t/gonemap` is keep-at-most-0, so its bodies drop as they die: possibly the residue limit of issues/deaths-dropped-superseder.md showing in the window, or a window that skips a copy it should play.

# A fallen purge request leaves the state an older stamp than its held bodies give
> Summary: After a demotion makes a purge request of one origin fall (its import `ic` off the list), the state of the copy's register holds origin `d`'s older value-less write, while a rebuild from the held bodies and residues gives `c`'s newer one (from the two-origin import's residue). Reads alike (both value-less) until a write stamped between them arrives. Found by the rebuild check.
> Tags: engine, retention

Repro: `moves::tests::repro_two_origin_import_stays_dropped_while_one_origin_is_purged` (osis-engine lib, `#[ignore]`; was `two_origin_import_stays_dropped_while_one_origin_is_purged`, whose own assertions passed). `cargo test -p osis-engine --lib moves::tests::repro_two -- --ignored`.

Setup: a moved thing's register `t:body.0`; writes `d` then `c` (commit form); imports `both` (c, d), `ic` (c), `id` (d); `x` admin purges `ic`, then `id` is purged; then the demotion of `x` (line 563, whose frontier leaves out the request on `ic`). The check fires in the demotion's transaction:

```
state of copy Ak("t:body.0") differs from a rebuild from held bodies:
  - kept 6:    stamp: (…131072000, C d:1),
  + rebuilt 6: stamp: (…196608000, C c:1),
```

Both value-less. `ix.valueless` lists only `d` afterwards, `ic` counts as not dropped (its body not held: the test then ingests a copy and reads c's value). So the un-merge or the fall's re-join wrote a state without `c`'s stamp, which `both`'s residue carries (the residue invariant in `apply::atomic::residues`). Likely in the purge-fall path (`retention::purge` taking `ic` back, `make_valueless` of `both`) rather than `rebuilt`, which agrees with the spec's join of held bodies and residues.

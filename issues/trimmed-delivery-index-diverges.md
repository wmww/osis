# A newcomer fed what its sync IDs carry, in a random order, keeps a live index unlike its store
> Summary: In engine `rotation::tests_carried::rotation_judged_alike_by_a_node_joining_after_compaction_spec_crypto_4`, the newcomer X handed `LocalPeer::packages_to(A, x)` (what its sync IDs carry, not every commit whole) in a random order fails the per-transaction index check: its live index holds `Held(tid)` as `([], false)` where its store loaded afresh holds nothing.
> Priority: normal
> Tags: engine

Repro: in that test replace `s.lp.packages(A)` (marked Interim) with `s.lp.packages_to(A, x)` and run `cargo test -p osis-engine --lib -- tests_carried::rotation_judged_alike`: panics at core/engine/src/engine/mod.rs (the index check, "opened from the persisted index ... the index Held(..): want ([], false), got <none>"). Whole delivery passes, so it takes a commit arriving with only some of its parts (certificates without bodies) to reach it. A live index entry a reload does not rebuild is state that differs across a restart: find the path writing `Held` that the load does not replay (or the reverse), then switch the site back.

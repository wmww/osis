# must_carry's invariant holds for cover, not for liveness
> Summary: `must_carry` (core/node/src/sync/pass/bodies.rs) promises that what one honest node deletes at a source no other's `must_carry` puts back. spec/sync.md §7 Carriers judges a part's liveness by the deleter's view, while a holder's `must_carry` asks its own: a right holder that finds a part dead (a later write it holds kills it) deletes every blob of the commit, and an author that finds the part live and uncovered places a fresh blob each pass, a message storm for as long as the views differ. Seen in sim `work_sets` and `member_churn` seeds that now pass (the views no longer differ there, the rule is unchanged); no current reproducer.
> Priority: normal
> Tags: sync, node-sync, sim

- Shape seen: a two-delta commit; the right holder dropped part 0 as covered by its own snapshot and found part 1 needs no carrier (not live there); the author keeps part 0 (spec/sync.md §7 Own bodies), finds part 1 live and covered by no snapshot it holds, so `delete_stands` fails on `must_carry(1)` and it places [0, 1] again each pass, which the right holder deletes. Which write made the views differ was not established.
- The drain moves no clock, so a disagreement gated on a relay wait or partition storms for its whole length.
- Former repros (pass on main): `cargo run --bin sim-sweep -- --seeds 1 --from 43254590194 --setup 43254590189 --only work_sets`, `... --from 720956814950 --setup 720956814942 --only member_churn`.

# work_sets: a liveness disagreement makes author and right holder ping-pong a blob
> Summary: sim `work_sets` setup 43254590189 seed 43254590194 fails at step 160 with "message storm: 5000 deliveries": the author of a two-delta commit places a fresh encryption every pass and a right holder deletes each one, the two judging one delta's liveness differently. Not the readable/whole-set rule of spec/sync.md §3.
> Priority: normal
> Tags: sync, sim

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 43254590194 --setup 43254590189 --only work_sets` (10 s).
- Commit `ebb9ff31..` (node 2's, step 130), parts 0 `s:hi.0` and 1 `s:reg.0` on one thing, under one label; both nodes read both parts (`readable` [0, 1] on each side).
- Right holder V dropped part 0 as covered by its own snapshot `ddb97e..` and deletes every blob of the commit as `Why::Dropped`. Its `carried` finds part 1 needs no carrier: `part_to_carry` is false, so at V part 1 is not live (and not kept).
- The author keeps part 0 (spec/sync.md §7 Own bodies), finds part 1 live (`part_live` true) and covered by no snapshot it holds (its own `d72cd9..`: `covered` None; `88bac2..`: false), so `delete_stands` fails on `must_carry(1)` and it places [0, 1] again each pass; every new blob holds part 0, which V dropped, so V deletes it.
- So V and the author disagree on whether `s:reg.0`'s write in that commit is live: V presumably holds a later write killing it that the author lacks or judges otherwise. Not established which. The drain moves no clock, so a disagreement gated on a relay wait or partition storms for its whole length. Spec/sync.md §7 Carriers judges liveness by the deleter's view, while the holder's `must_carry` asks its own: the invariant in `must_carry`'s doc ("what one honest node deletes at a host no other's `must_carry` puts back") holds for cover but not for liveness.
- Same storm shape in `member_churn` setup 720956814942 seed 720956814950 (step 56: s0 deleting and re-adding one content commit's chunk blobs, `s:reg.0`): `cargo run --bin sim-sweep -- --seeds 1 --from 720956814950 --setup 720956814942 --only member_churn` (5 s). Not checked whether it is the same mechanism.

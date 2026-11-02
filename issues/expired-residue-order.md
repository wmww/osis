# An expired write's residue depends on arrival order, and an older value can show
> Summary: a node holding an expired write and another peer's snapshot of it keeps the value-less write in the aspect's state in one order and no state in the other. With an older write held too, one order reads absent and the other the older value. A violation of spec/requirements.md Decentralization in reads; spec/crdt.md §4.7.
> Tags: tests, crdt, engine, retention

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_expired_residue_order_spec_crdt_4_7`: order seed 626233's generated history, five commits of it held (H's creation, a role commit on G, 0's write on H with an expiry past `now` and a second aspect, 2's compaction of it, a second role commit on G). The states differ; both read absent. A scripted history of the same shape did not reproduce it, so the repro plays the generated one. The read difference: `OSIS_ORDER_SEED=626233 cargo test -p osis-node --test it order::arrival_order_alike_large -- --ignored`, a larger held set: as made absent, reversed `v0`, an older write of the register (from a `Forged` step in that history: not read further, so whether honest commits alone reach the read difference is open).

Not diagnosed. Start at `retention::make_valueless` and `apply::atomic::residues`; the snapshot may be invalid in the end (2 demoted), and its value-less copy (§4.7: snapshots carry an expiring delta's writes value-less) may be stripped in one order only.

No skip in the order harness: anything narrow enough to name this would hide a read. So the large oracles fail on such seeds until this is fixed (1 of 300 fresh seeds); a failure on `t:reg.0` with an expiring write is this one.

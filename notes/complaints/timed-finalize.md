# timed-finalize complaints
> Summary: Footguns met building the timed-edge finalize.

- Test harnesses wrote admin removals with no frontier (set_edge, remove_holder, order's edge_write, walks' try_edge): 25 tests broke at once when a frontier-less removal became a finalize. They now carry an empty frontier; new harness removals should too.
- The judgment vectors embed commit bytes: any change to a harness commit's shape needs `OSIS_WRITE_VECTORS=1 ... judgment_vectors_write`; check the diff changes only hashes.
- A void role write still resets the CRDT entry: a later removal emitting only `Op::Remove` wrote no `roles.0` delta at all (silently a bare rotation). Removals now also reset every seen entry of the holder.
- The sim harness's `revoke` (core/test/sim/src/harness.rs) also wrote frontier-less removals; tier 1 passed and only the sim sweep caught it.

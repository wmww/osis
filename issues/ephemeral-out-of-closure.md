# A thing out of every closure can read differently; a rule that ends that
> Summary: for Tess: nodes can read an unlisted ephemeral thing differently (spec/sync.md §9 Out of every closure); keeping a thing in a label's closure once a commit on it was kept there removes the limit and `going_whole`, but an unplaced thing's writes keep reaching that label. Also the cost of the `parked` walk.
> Tags: ephemeral, node-sync, tess-call

**Today.** After a demotion drops the only placement of a thing, the thing is listed nowhere. Each node keeps what it holds: a snapshot made then goes nowhere (`MemorySync::parked`), and the reconcile after a fallen snapshot goes by closure, which has just lost the thing. Seeds 132, 1472 of `ephemeral::ephemeral_reverts_within_rights_alike_large_spec_crdt_4_6`: 24 of 3000 seeds, every one with no group listing the thing. The oracle skips those reads.

**The rule.** `in_ephemeral_closure(g, t)` also holds once a commit on `t` was kept under `g`'s label here. Tried (not merged): no difference in 3400 oracle seeds, skip off, with `going_whole` and whole placement removed too; tier-1 `ephemeral::` green.

**The cost.** Later writes of a thing unplaced from a group keep going under that label, while its actor may read them, until the thing is freed or the node restarts. Unplacing would no longer stop syncing. Needs a new per-thing, per-label set in memory.

**Parked walk.** `take_memory_commits` checks every parked commit each `eph_step`, and a write on a local-only thing runs a step, so a write costs O(parked), against "well under a millisecond". Compaction keeps parked commits to a few per aspect. Not measured; many live local-only things would show it. If it does: walk only when a placement or group changed.

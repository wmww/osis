# A snapshot's frontier stops for good at a body that left with no carrier
> Summary: A node missing a body that left hosts with no carrier, or a part its commit applied without, writes snapshots whose frontier stops for that author on that aspect. They cover none of the author's later bodies and no snapshot reaching past the gap. Only a node that held the body can compact past it. State is bounded by the author's bodies on that aspect; reads converge.
> Tags: engine, sync, retention

Frontiers count contiguous counters (`Engine::snapshot_if`). A gap is a counter whose header is not held (the whole body left: the same on main before atomic-carrierless) or whose part is missing with no expiry (`waits::snapshot_after_release_leaves_part_to_join_spec_crdt_8`).

Effect: the node's compaction of that aspect drops nothing of the author's from the gap on. A snapshot from a node with no gap covers its bodies and its gapped snapshot alike, turning the missing part into a dropped one, so the next frontier reaches. If every such node is gone, the bodies stay until their own bounds; those with live writes and no bound stay for good, and their snapshot is not replaced. Compaction is explicit, so no snapshots pile up.

Claiming the gap is not the fix: the snapshot would then cover a part that may be live, and its late copy is refused. Nor can `covered` refuse a missing part under a claim: a holder's snapshot, which does carry it, reads the same. Fix sketch: frontiers with holes, which the wire does not have (`[[Src, ctr]*]`).

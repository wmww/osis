# Some edits of long texts still cost a whole placement pass
> Summary: Most edits of a long text or list join and place in proportion to the edit (osis-crdt `small_joins_follow_cached_placement_spec_6`), but a set of cases still fall back to a whole placement pass (O(n)), and a received delete of the whole sequence costs O(n) by nature.
> Priority: low
> Tags: performance, crdt

Fallbacks to a whole pass (the full list: osis-crdt `seq_lin` module doc):
- resets (O(n) by nature: every older element re-anchors on END; the bare records merge into range records, so the next pass places a node per stretch);
- a new `Derived` record or an anchor at an absent one, 256 or more newer siblings at one anchor;
- moves: an element on a cycle a demotion broke (`Lin::cyc`), a move closing a cycle, an unknown written or dropped anchor, a dropped anchor inside a range record, a sibling a move in the same delta pushed out of its top two. Following broken cycles exactly needs cycle groups and a local §6.2 re-run: a second cycle breaker, the moving part this cache avoids; cycles need two or more concurrent moves of one range;
- a received delta with more than max(√n, 64) runs, moves and row cuts, or placements costing more than about a pass (by design: hostile deltas cost at most about two passes).

Other O(n) costs:
- A received delete of all of a long text (what `Set` of a new value sends): every element record takes the flag.
- `DeltaBuilder` copies the position's state where a reset of the delta lies above it, and rebuilds its layered view after an op removing an element the same commit made or dropping an anchor at one.
- The dot map is built with every rebuild; its chunks split but never merge between rebuilds (merging would need `PlaceDiff` to carry gone chunks for osis-engine `pages::write_place`).
- Texts at a `Slots` position: a join changing the register or raising the reset re-embeds and prunes every slot.

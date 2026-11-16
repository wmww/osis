# Sequence element retention dates later than the spec
> Summary: Two places retention keeps a sequence body longer than spec/commits.md §5 and spec/crdt.md §4.8 say, never shorter: an element record counts live for its creator after the creation is pruned, and a creation counts live once an undelete wins over the delete. Kept longer, never lost.
> Priority: low
> Tags: retention, crdt

## A sequence record holding only others' writes keeps its creator's body live
spec/commits.md §5 counts every sequence element record of a body's deltas the state holds as a live write of that body, "also one holding only others' writes" (`Fragment::live_writes` lists a record's dot whatever it holds). Once the creation is pruned, the creator's body adds nothing to the state (a record with no creation places at END, like a node that never held it), so it should be dead; counting it live keeps the body, and its delete at peers, longer than needed.

A leak, not a wrong read: keeping more is safe. Fix: a sequence record counts for its creator only while it holds the creation (as a map entry counts by its creation), in `walk.rs` `Writes::rec` (`Rec::Seq`) and spec/commits.md §5; then `bounds::snapshot_live`'s "a write without a `ts`" covers only tombstones. Check with a hand-written case: text typed, a char deleted by another writer, then a reset newer than the creation but older than the delete flag; `bounds::live` of the typing body turns false once the reset lands.

## A text creation under a later undelete dates no death
Retention judges a text element's creation by the element's winning flag (`Fragment::winners`), so once an undelete (or a reset sparing a later creation) wins over the delete, the creation counts live and the inserting body is not dated at the delete; spec/crdt.md §4.8 has it dead from the earliest delete on. Kept longer, never lost.

held-model counts it as the `keep-for-D dated later` tally (core/test/held-model/AMBIGUITIES.md item 27). Fixing it needs either the spec to say an undelete revives the creation, or deaths judged against more than the winners of the state (the delete is gone from it).

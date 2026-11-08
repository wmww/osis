# A sequence record holding only others' writes keeps its creator's body live
> Summary: spec/commits.md §5 counts every sequence element record of a body's deltas the state holds as a live write of that body, "also one holding only others' writes" (`Fragment::live_writes` lists a record's dot whatever it holds). Once the creation is pruned, the creator's body adds nothing to the state (a record with no creation places at END, like a node that never held it), so it should be dead; counting it live keeps the body, and its delete at hosts, longer than needed.
> Priority: low
> Tags: retention, crdt

A leak, not a wrong read: keeping more is safe. Fix: a sequence record counts for its creator only while it holds the creation (as a map entry counts by its creation), in `remap.rs` `Writes::rec` (`Rec::Seq`) and spec/commits.md §5; then `bounds::snapshot_live`'s "a write without a `ts`" covers only tombstones. Check with a hand-written case: text typed, a char deleted by another writer, then a reset newer than the creation but older than the delete flag; the typing body is replaced once the reset lands.

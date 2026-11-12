# A replaced large value's tree is unweighed by the compaction trigger
> Summary: the trigger weighs a body by its deltas and the pages they link, either class; the tree nodes and chunks of a large value it replaced, which a drop frees, go uncounted, so an aspect of large-value edits compacts later than `FACTOR` says.
> Priority: low
> Tags: engine, retention

The trigger (`retention/compact.rs` `body_bytes`, spec/sync.md §7 Trigger) weighs a body by what dropping it frees: its deltas and their pages (`apply::memory::each_page`: listed blobs reached from the delta that are not tree nodes). A large value's tree is skipped, since the live state, so the snapshot, keeps linking it while the value is live (counting it made every large-value write fire the trigger). Once the value is replaced a drop frees its tree, uncounted.

The exact rule is "listed blobs no live state links": exclude the blobs the snapshot being weighed links (`large::delta_links` of its encoding) at weighing, and count a replaced value's tree when its body leaves history or is replaced (`Trigger::counts`).

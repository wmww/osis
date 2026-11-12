# Durable pages unweighed by the compaction trigger
> Summary: the trigger weighs an ephemeral body with its pages but a durable one by its deltas alone; a durable delta past a blob has pages a drop frees that go uncounted.
> Priority: low
> Tags: engine, retention

The trigger (`retention/compact.rs` `body_bytes`, spec/sync.md §7 Trigger) weighs a body by what dropping it frees. An ephemeral body's listed blobs are all its pages (values are inline), so they count. A durable body's chunk list mixes its large values' chunks and tree nodes, which the live state and so the snapshot keep linking (a drop frees none of them while the value is live), with the pages of a delta past a blob, which a drop does free. Counting the whole list made every large-value write fire the trigger (the snapshot links the chunks and costs almost nothing); counting none leaves durable pages out, so an aspect of paged durable deltas compacts later than `FACTOR` says.

The exact rule is "listed blobs no live state links". Options: tell pages from value trees when walking a delta (pages are reached as page links of the crdt encoding, trees as value links), or exclude the blobs the snapshot being weighed links (`large::delta_links` of its encoding) at weighing and keep the estimate (`Trigger::counts`) to deltas plus pages.

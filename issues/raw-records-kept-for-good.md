# Raw records are kept for good
> Summary: Every creation record a node learns raw (`Engine::learn_records`, from a record blob or an inbox payload) is stored as a `t/` row for good, whether or not anything held needs it; a label's writer (or an admitted inbox sender) can grow every reader's record table.
> Priority: low
> Tags: engine, node-sync

- A record proves itself by its hash, so learning one needs no authority, but nothing drops a raw record whose thing the node never holds a creation or part of. Record blobs are certificate blobs (no delete key), and their records outlive them at every reader.
- Bound: what a writer can place under the label (blob caps) or an admitted sender can seal; no worse than other writer-placed data, but it never goes.
- Fix shape: keep a raw record only while something held names it (a part on its thing, a record or edge write naming it, an awaited chain), and forget it with the last such; or learn only records an awaiting commit or chain asks for, reading the label's record blobs again on the wake (`Kind::Records` lists their tids).

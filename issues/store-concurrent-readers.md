# Store has one handle: reads serialize with writes
> Summary: `Store` needs `&mut` for every read (reads go through a `Transaction`), so the node must hold it behind one lock and a long streaming read interleaves page by page with writers. The store design wants "many handles, one writer". Rows are versioned, so snapshot readers over a committed `r` pointer are possible; deferred until node-core shows the need.
> Tags: storage

Repro: design, no failing test.

Options: (a) keep one handle (node locks per call; streams resume by key); (b) read-only snapshot handles pinned to a committed version, with cleanup of superseded rows deferred while a snapshot is open (needs a reader registry, and redb read transactions per snapshot); (c) a reader-writer lock in the node. Recommended: (a) until profiling says otherwise.

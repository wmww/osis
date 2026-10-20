# One device's reads and writes take turns at the local store
> Summary: The local store has one handle, so on one device a long streaming read (say of a multi-gigabyte value) and a write share the store page by page instead of running fully in parallel. No user-visible stall is expected (streams resume by key between pages); true snapshot readers are a known design (versioned rows) deferred until profiling shows the need.
> Tags: performance, storage

Repro: design, no failing test.

`Store` needs `&mut` for every read (reads go through a `Transaction`), so the node holds it behind one lock and a long streaming read interleaves page by page with writers. Rows are versioned, so snapshot readers pinned to a committed `r` pointer are possible. Options: (a) keep one handle (node locks per call; streams resume by key); (b) read-only snapshot handles pinned to a committed version, with cleanup of superseded rows deferred while a snapshot is open (needs a reader registry and redb read transactions per snapshot); (c) a reader-writer lock in the node. Recommended: (a) until profiling says otherwise.

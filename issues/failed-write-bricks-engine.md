# One failed write leaves an engine unable to write until its node restarts
> Summary: A one-off failed durable write (`Fault::Fail`: EIO, a full disk that frees up) leaves the engine's `Store` broken (`Error::Broken`) and nothing reopens it: every later transaction of that node, or of a host's node sync, fails until the process restarts. The hub's `HostStore` recovers in place (`Store::reopen`). The sim never injects `Fault::Fail`, so no net-level run reaches this.
> Priority: normal
> Tags: engine, store, sim

- Seen in tests: node `lifetimes.rs` ("a failed write breaks the store until the node opens again") and engine `failing` both restart the node after a failed write. Nothing in core/engine, core/node or core/osis calls `Store::reopen`.
- What is in place: a failed transaction rolls the journaled indexes back (engine `failing` checks it), and `Engine::run` settles blobs before the next transaction after a failed commit (`blobs_unsettled`). Only reopening the store is missing (`HostStore::commit` does it on failure).
- Fix: reopen the engine's store in place after a failed commit, as `HostStore` does; check that the in-memory state after a reopen equals a fresh open (the rebuild check). Then add `Fault::Fail` beside `Fault::Crash` in the sim's planned faults (the device stays up, its next calls must work), and a small node test: a write fails once, the next one works with no restart.

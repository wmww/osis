# On redb a failed write still needs the store opened again
> Summary: The store recovers in place after a failed write, but redb (the product backend, `RedbBackend`) poisons its `Database` after any I/O error: every later call fails `PreviousIo` until it is opened again. So recovery fails, the store is lost (`Error::Broken` until reopened), and nothing reopens it: a one-off EIO or full disk still stops a real node's writes until the process restarts. Only `MemoryBackend` (tests, sims) recovers in place.
> Priority: normal
> Tags: store, durability

- Seen by reading redb 2.6 (`CheckedBackend::check_failure` in `tree_store/page_store/cached_file.rs`; its own test `transient_io_error` expects `begin_write` to fail `PreviousIo` after a failed commit). No osis test injects a fault into redb: the redb crash tests fault `FileRoot` slot writes only.
- Fix: `RedbBackend` reopens its `Database` after a failed call (drop it, `Database::create` again: redb repairs on open), so `Pager::recover_in_place` reads the file as an open would. Test with a redb `StorageBackend` wrapper that fails one write (`redb::Builder::create_with_backend`): a failed commit at each write recovers in place and the next transaction works, on redb as on memory.

# A destroyed thing's record learned again for good
> Summary: The facade learns a record from a record blob kept loose as soon as something here awaits it (`take_record_blob`, `Engine::promote_loose`). A minting of a thing destroyed for good awaits its record too (`thing_wait` answers `UnknownCreated`), so where a loose record blob carries it the record comes back and stays for good, with the minting awaiting forever. No revival; the cost is one kept record per such thing.
> Priority: low
> Tags: engine, sync

- Reach: any writer of a sync ID whose record blobs carry the destroyed thing logging a minting of it there (a dependent once needed the record; record blobs carry no delete key, notes/growth.md).
- Fix options: a minting of a thing destroyed for good awaits nothing (it is never taken, `thing_wait`'s `for_good`), so it should not count in `awaits_record`; only a dependent's wait (`Reason::MissingChain`) or a part on a thing not destroyed for good learns a record.
- `Engine::destroyed_records_awaited` (core/engine/src/apply/mod.rs) has no caller: the old sync's relearn path.

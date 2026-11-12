# A minting of a thing destroyed for good brings its record back for good
> Summary: node-sync relearns a destroyed thing's record from a held record blob whenever something awaits it (`settle_batch`, `Engine::destroyed_records_awaited`). A minting of a thing destroyed for good awaits its record too, so where a record blob carrying it is held the record comes back (`learn_record` notes it kept) and nothing judges its keep again: it stays for good, with the minting awaiting forever. No revival, cost as main's per-purged-thing record; a leftover the branch meant to remove.
> Priority: low
> Tags: engine, sync

- Reach: any record holder posting a minting of a purged thing under a label whose record blobs carry it (a dependent once needed it; record blobs stay, notes/growth.md row 5b).
- Repro sketch (`destruction::` setup): b purges t (grant on t), past the window every node is marked; then at b `learn_records(vec![rec])`: the record stays held over ticks and a restart. The sync path takes the same step when a hostile minting awaits t.
- Fix options: relearn only for a dependent's wait (`Reason::MissingChain`), never for a part on the thing itself once it is destroyed for good (its minting is never taken, its other parts matter only to a dependent, `record_back`); or judge the keep again after the batch settles (churns once per batch while the minting awaits).

# A removed sync holder keeps its sync record
> Summary: after a removal's notice stops a node keeping S unread (S shredded with its path), the node still has the thing's sync record and lists S as kept unread; reproducer `keep::a_removed_sync_holder_keeps_no_record_spec_sync_judgement_6`, ignored.
> Priority: normal
> Tags: sync, tests

- Seen over real connections only (the by-hand version of the test carried each inbox blob once): the store is shredded, `removal_notices(S)` holds the notice, but `sync_record(t)` holds the grant's sync secret again and `sync_holding(S)` is `Unread`.
- Suspected: the grant's inbox blob is still held (unexpired, deposited) in the node's inbox, and taking it again after `drop_sync_record` writes the record anew (`records::note_sync_secrets` makes a record from any box that opens). A notice at or past the record's sync epochs (spec/sync-judgement.md §6 Stops) should keep a later take of an older grant from making a record; check whether the notice counts against the re-taken blob's epoch.
- Then S is kept unread again with no path: harmless until a Register arrives, when the removed node would hold S again.

# A grant again is lost to a failed durable write at the grantee
> Summary: a sync holder raised to write, removed, then granted read again while one of its durable writes fails never gets the read grant: at quiet it lacks the granter's grant commit and reads the roster without its own edge. Ignored test `flows::a_member_granted_again_through_a_failed_write_reads_its_grant`.
> Priority: critical
> Tags: sync, inbox

Property: a grant reaches its grantee (spec/sync-inbox.md §2 Re-send: the sender re-sends until it has seen the recipient take it; spec/sync-ids.md §5: the store is the truth after a failed write).

Trace (faulty differential, seed 347110579992 shrunk from 46 steps): node 0 makes thing 0, writes v2, grants node 1's account sync; run; grants it write, removes it; run; node 1's 3rd durable write from now fails (`Disk(1, 3, Fail)`); node 0 grants node 1's account read; node 1 writes thing 0 (`Write(1, 0)`, a write by a removed member); healed, run to quiet.

At quiet node 1 reads v2 with roster [node 0's account Admin]; the reference and node 0 list node 1's account as Read. Node 1 lacks node 0's read-grant commit and has no invitation; handing it node 0's commits by hand gives it the grant. Without the failing write, or without `Write(1, 0)`, it converges; the failure at node 1's 2nd or 4th durable write fails the same way, at its 1st it converges.

Suspected: the inbox's Re-send (the sender counts the grant taken from something node 1 showed before its failed write lost the take) or node 1's take of the inbox blob after its store is read again (the inbox position kept past a blob whose take did not stand). Close relatives that pass: `flows::a_writer_granted_again_after_a_failed_write_reads_spec_sync_inbox_2`, `flows::a_reader_granted_again_through_a_failed_write_reads_spec_sync_streams_4`.

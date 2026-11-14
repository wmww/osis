# A grant, its removal and a grant again pending together leave the grantee short
> Summary: the differential's last failures (3 of 200 histories at sync-integrate-4): a grantee granted, removed and granted again before the first grant reached it reads the roster but not every value (the removal's later writes, or the value itself); three minimal reproducers in core/sync/tests/it/flows.rs, ignored.
> Priority: normal
> Tags: sync, tests

- Reproducers (flows.rs): `a_reader_granted_again_reads_what_a_snapshot_carries_spec_sync_judgement_3` (clean seed 78: write, grant, grant, remove, write, grant again, no run between), `a_writer_granted_again_after_a_failed_write_reads_spec_sync_inbox_2` (seed 77), `a_reader_off_through_a_grant_a_removal_and_a_grant_again_reads_spec_sync_inbox_2` (seed 93).
- Seen on seed 78: the grantee holds both read epochs established and has S open at the writer, yet holds none of S's entries; the writer judges the last write covered by a compaction snapshot (the per-step compaction trigger made one) whose blob it sealed but did not log under S, so nothing of the value is served. Check `judge::body`'s Log for a snapshot (must-hold, `covered: Some(false)`) and whether `log_own`'s verbatim path or `seal_body` refused it.
- Related fixed cases (tests in flows.rs): a delivery is not seen taken by an open by an older read secret or by a sync holder's store credential; a role change moves `changed_at`; a shred drops S from every record.

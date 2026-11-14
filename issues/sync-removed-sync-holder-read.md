# A sync holder removed and granted read does not read
> Summary: node 1 grants node 2's account sync on a thing, removes it, then grants it read while the two are partitioned: once healed node 2 reads no value, the reference reads v1. Deterministic reproducer `flows::a_sync_holder_removed_and_granted_read_while_away_reads` (ignored); found by the full-size differential.
> Priority: normal
> Tags: sync, tests

- Not investigated. Close to `flows::a_read_grant_after_a_sync_removal_reaches_the_grantee_spec_sync_inbox_2` (passes), which has no partition.
- Faulty seed 188669321805 shrinks to the same shape with a lossy network and a skewed clock (things made, `Grant(0, 3, 2, Syncs)`, `Run`, `Remove(0, 3, 2)`, `Grant(0, 3, 2, Reads)`: node 2 reads no value, the reference v13). Faulty seeds 188669321416 (node 0, a reader, reads v11, the reference v12) and 188669321645 (node 2 lacks a Sync role row the reference has) fail on every replay and were not shrunk; they may be other classes.

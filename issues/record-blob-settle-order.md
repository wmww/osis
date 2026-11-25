# Two readers' record blobs settle by arrival, not by the winning rule
> Summary: osis-sync `keep::readers_logging_the_same_records_settle_on_one_record_blob_spec_permissions_4` fails when account making (`osis_engine::local_peer::make_account`) writes the node root's strong to A and its `settings^.0` in one commit: node 1 keeps a record blob of a lower ID than the one the writer keeps, so they do not settle on one. The commit shape only moves the world's rng; the winning rule (spec/permissions.md §4 Logging certificates: more records, else lower blob ID) should hold for any IDs.
> Priority: normal
> Tags: sync, tests

Seen: with that root write as one commit (main writes it as two), the test's assert at keep.rs:208 reads `left: [35b46a07..]` (node 1) against `right: [2714732a..]` (node 0's one): node 1's held blob is not node 0's, and node 0 keeps the higher ID. Not probed further. Reproduce by merging the two root commits at the end of `make_account` (core/engine/src/flows/roots.rs) and running the test; then write a hand-built world (two record blobs of the same records, IDs ordered by construction) as the test, seed 0, and fix the rule.

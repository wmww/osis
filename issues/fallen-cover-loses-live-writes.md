# A fallen cover loses the live writes it alone carried
> Summary: With the state exactly the join of the held bodies, a body dropped as covered whose cover then falls (purged, or turned invalid) is "missing again, fetched", but compaction already deleted it at the hosts on the cover's strength, and readers upload nothing; so its live writes are lost at every writer and fresh node while stale readers still show them. Repro `deletion::repro_purged_cover_loses_live_writes_spec_permissions_5_2`.
> Priority: normal
> Tags: engine, retention, sync, tess-call

Repro: admin a writes v2, compacts (snapshot S covers the body, the host deletes it), then purges S by name. Reader r, away through the compaction, still holds the body. After sync: a and a fresh reader f read nothing, r reads v2 (it cannot upload: no write key). The order and held-model harnesses miss it: they exchange bodies by hand, so "missing again, fetched" always finds a copy.

Also reached by: a purge by author of the compactor (its snapshots are its deltas), and a cover turning invalid (spec/permissions.md §5.2: the compactor demoted with a frontier not listing the snapshot), whose repair (`suspect::Why::Uncovered`, a writer re-snapshots) carries only what the writer's state holds, now nothing of the lost bodies.

Simple rules to choose from:
- a purge naming a snapshot holds it as its leftover (its copies of the named writes value-less), like every other body carrying their values (spec/commits.md §5 Purge), so a purge never drops a cover; leaves the invalid-cover case;
- hosts keep a covered body until its cover is uploaded and settled valid (no such point: forks are permanent);
- a writer dropping a snapshot other than as covered first writes a replacing snapshot from the old one's content minus what is purged (rare path, brute force); for an invalid cover that content is unvouched (history verified or absent), so the covered bodies' live writes are lost there by design and the limit is stated.

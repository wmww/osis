# node-sync skips the purge re-snapshot for a wholly purged delta
> Summary: spec/commits.md §5 Purge says a writer holding no covering snapshot after applying a request re-snapshots; node-sync does so only from `snapshot_first`, when deleting a body with live writes, so a plain delta purged whole (no live write: `part_valueless`) is deleted with no re-snapshot, and a node that never held it reads what it replaced until a writer next writes or compacts.
> Priority: normal
> Tags: sync, engine, tests

- Where: `core/node/src/sync/pass/delete.rs` `deletable`: `!live` gives `carried`, so `snapshot_first` never runs for it. The only other purge re-snapshot path is a carrying snapshot stripped of the values (`deletion::purge_resnapshot_by_writer_without_schema_spec_commits_5`).
- The order harness models the spec rule (`order::resnapshot`, run by the purger only); its seeds 743309, 452234901986, 632724249436 fail without it, so a networked node shows the divergence the spec meant to repair. Reachable: Bob writes over Alice's value, an admin purges Bob's write by author; a node that dropped Bob's body as invalid (or followed the thing later) reads Alice's value.
- Fix: after applying a request, each writer of a named aspect holding no snapshot covering the named bodies it held writes one (node-sync, on the engine's purge event), as spec says. Test: a node-sync test of that history, failing with the fix disabled.

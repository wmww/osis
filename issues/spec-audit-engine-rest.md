# Engine parts the spec audit has not compared with code
> Summary: What is left of the engine spec audit: the host side of purge.
> Priority: low
> Tags: spec, engine

## Not audited
- Node-sync's half of purge: host deletes and rewrites (`sync/pass/delete.rs`), spec/sync-ids.md §6, spec/sync-judgement.md §2, spec/sync-compaction.md §1. Engine side done; the re-snapshot after a purge only spot-checked (`deletion.rs` test).

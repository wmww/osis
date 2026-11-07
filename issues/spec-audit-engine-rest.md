# Engine parts the spec audit has not compared with code
> Summary: What is left of the engine spec audit: the host side of purge.
> Priority: low
> Tags: spec, engine

## Not audited
- Node-sync's half of purge: host deletes and rewrites (`sync/pass/delete.rs`), spec/sync.md §5, §6, §7. Engine side done; the re-snapshot after a purge only spot-checked (`deletion.rs` test).

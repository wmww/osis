# Engine parts the spec audit has not compared with code
> Summary: What is left of the engine spec audit after deaths, purge, ephemeral creation undo and crdt-model undo were compared: the host side of purge, and open questions.
> Tags: spec, engine

## Not audited
- Node-sync's half of purge: host deletes and rewrites (`sync/pass/delete.rs`), spec/sync.md §5, §6, §7. Engine side done; the re-snapshot after a purge only spot-checked (`deletion.rs` test).

## Questions, not traced to a concrete harm
- A held later compaction snapshot counts as a later change in effect, so step-back stops after any compaction here (literal §4.6, same in code); intended?

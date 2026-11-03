# Spec audit 2 leftovers: engine parts not yet audited
> Summary: What is left of the engine spec audit after deaths, purge, epoch-start rounds, ephemeral creation undo and crdt-model undo were compared: the host side of purge, and open questions.
> Tags: spec, engine

## Not audited
- Node-sync's half of purge: host deletes and rewrites (`sync/pass/delete.rs`), spec/sync.md §5, §6, §7. Engine side done; the re-snapshot after a purge only spot-checked (`deletion.rs` test).
- `Input::cyclic` and resuming a timeline from old starts (spec/permissions.md §6 says rounds begin from none): the fixed-point argument in `walk::drive` read, not proved; `check_scratch` tests it in debug builds.

## Questions, not traced to a concrete harm
- `chain_judge` (engine/src/undo/mod.rs:332): `undone_by` holds every held undo commit naming a commit, whatever its validity, and an invalid later commit counts as "in effect". §4.6 does not say whether an invalid undo commit undoes, or whether an invalid delta "holds writes of the aspect". Effect limited to undo's step-back.
- A held later compaction snapshot counts as a later change in effect, so step-back stops after any compaction here (literal §4.6, same in code); intended?

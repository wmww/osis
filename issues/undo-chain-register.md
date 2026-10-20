# Undo cannot step back twice on one register
> Summary: spec/crdt.md §4.6 writes a register's previous value only while the undone write is the current winner; after one undo the winner is the undo commit's restoring write, so undoing the write before it writes nothing and an undo stack stops after one step per register.
> Tags: crdt, api, owner-call

Repro: osis `tests/history.rs` `undo_redo_cycle_spec_commits_7` (asserts today's `NotUndoable { Superseded }`).

Sequence on one register: write 1 (C1), write 2 (C2), undo C2 (U writes 1 with a fresh dot), undo C1: C1's write is not the winner (U's is), so no write; the value stays 1. Undo/redo of a single step works, and undo walks across different aspects, so only repeated undo inside one register (a title edited twice) is affected. `Osis::undo` reports `Error::NotUndoable { reason: Superseded }` here and undoes nothing older (crates/osis/tests/history.rs `undo_redo_cycle_spec_commits_7`).

Options:
1. (recommended) §4.6: an undo of a register, case or position write also writes the previous value when the current winner was written by an undo commit in effect whose target (transitively) superseded the undone write. Local judgment like today's rule; no wire change.
2. Undo restores by re-instating the original dot (cancel the superseding writes instead of writing a new one): closer to Kleppmann & Brattli, but needs per-dot cancel records in the state.
3. Accept: one undo step per register; apps keep their own local undo for text fields (the text session's undo covers typing).

# Undo with no record in its buffer differs from spec and model
> Summary: Where the undo buffer lacks an element (older bodies dropped, not a recent local commit), osis-crdt's sequence undo inverts flags and restores positions on rules the spec does not state and that change with whether any older body is held. A `Slots` buffer position also reads differently from the model.
> Tags: crdt, tests

`seq_ops::undo` (core/crdt/src/seq_ops.rs:372), against spec/crdt.md §4.6:
- Text flag: "`false` only for an element visible in the undo buffer, `true` ... only for one deleted there". `was_visible` and the undelete arm pass when `before` is `None` (no sequence in the buffer). With `before` present and the element missing: no undelete. So a node with no older body undeletes and one with some older body does not. The model inverts a delete in both cases and an undelete in neither.
- Position: "(from the undo buffer ...) none when the previous value is absent". The engine falls back to the state's `prev` when the undone write is still `cur`; the model writes nothing.

`before_read` (core/crdt/src/undo.rs:72) reads the buffer position's chosen slot; the model reads the slot of the delta's encoding. spec/crdt.md §7 says only how the current winner is judged. If the chosen slot's value does not fit the view, `replace` returns `Mismatch` and the whole undo fails (traced, not run; needs two schemas on one AK).

Undo commits are ordinary writes, so nothing diverges; only what an undo restores. Decide the rule for a missing record, then align code, model and §4.6. `Fragment`-level differentials always give a full buffer, so none of this is tested.

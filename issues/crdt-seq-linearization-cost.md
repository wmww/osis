# Moves and multi-edit commits on long texts still cost a whole pass or a copy
> Summary: On a 100,000-character text, typing, deleting and concurrent typing at one spot cost microseconds per received edit, but a received move (cut and paste, drag) costs about 18 ms before the next read, and a local commit holding several edits costs about 15-22 ms (one copy of the text's state); both grow linearly with text size.
> Tags: performance, crdt

Repro: `cargo test --release -p osis-crdt --lib -- --ignored budget_big_text_spec_6 --nocapture` prints the times (notes/crdt.md Timing).

Remains:
- Fallbacks to a whole pass (~23 ms at 10^5): moves (position writes on existing elements), resets, range-record splits, `Derived` dots, an older insert at HEAD below a newer HEAD child, two runs anchored at one existing node in one delta, an older insert whose newer siblings' subtrees span more than 4096 rows. Moves are the common one: re-placing the moved subtrees (remove their rows, re-insert at the new anchor, detect a cycle by walking the new anchor's parents) is not built.
- `Batch`: from the second op on, ops resolve against a copy of state ⊔ batch (one per commit, ~12 ms to make and ~8 ms to drop at 10^5). Avoiding it needs a layered view (state records under the batch's) that seq ops and the cache can read, or a `Batch` owning the state.
- List `read` still looks up each visible element's record (text reads chars from the cache).

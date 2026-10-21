# Moves and multi-edit commits on long texts still cost a whole pass or a copy
> Summary: On a 100,000-character text, receiving typing, deletes and concurrent typing at one spot costs about 10-30 µs per edit, but a received move (cut and paste, drag) costs about 21 ms before the next read, and a local commit holding two or more edits of the text costs about 20 ms for the second edit (a copy of the text's state); both grow linearly with text size.
> Tags: performance, crdt

Repro: `cargo test --release -p osis-crdt --lib -- --ignored budget_big_text_spec_6 --nocapture` prints the times (notes/crdt.md Timing; received deltas go through encode and decode).

Remains:
- Fallbacks to a whole pass (~23 ms at 10^5): moves (position writes on existing elements), resets, range-record splits (a write covering part of a state range record, e.g. on text bootstrapped from a snapshot), `Derived` dots, an older insert at HEAD below a newer HEAD child, two runs anchored at one existing node in one delta, an older insert whose newer siblings' subtrees span more than 4096 rows. Moves are the common one: re-placing the moved subtrees (remove their rows, re-insert at the new anchor, detect a cycle by walking the new anchor's parents) is not built.
- `Batch`: the second op at a sequence position the batch already wrote copies that position's state joined with the batch (~12 ms to make, ~8 ms to drop at 10^5); later ops at the same position reuse the copy, but an op elsewhere drops it and the next one copies again. Avoiding the copy needs a layered view (state records under the batch's) that seq ops and the cache can read, or a `Batch` owning the state.
- List `read` still looks up each visible element's record (text reads chars from the cache).

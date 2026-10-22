# Some edits of long texts still cost a whole placement pass
> Summary: On a 100,000-character text, typing, deletes, moves and multi-edit commits now cost tens of µs, but a write that splits a range record (common on a text bootstrapped from a snapshot), a reset, or a move of elements caught in an earlier move cycle still costs a whole pass (~23 ms at 10^5) before the next read.
> Tags: performance, crdt

Repro: `cargo test --release -p osis-crdt --lib -- --ignored budget_big_text_spec_6 --nocapture` prints the times (notes/crdt.md Timing; received deltas go through encode and decode).

Remains:
- Fallbacks to a whole pass: range-record splits (a write covering part of a state range record; splitting a row would need, for a creation chain, the rest of its subtree one level deeper, which `Placement::reshift` already does), resets, `Derived` dots, a move of an element on a cycle a demotion broke (`Lin::cyc`) or one closing a cycle, more than 256 newer siblings at one anchor.
- `Batch` still copies the position's state where its records do not line up with the state's (the same range splits) or a reset of the batch lies above the position.
- List `read` looks up each visible element's record (text reads chars from the cache).
- The placement cache's dot map folds its added entries into its base past √n; when the base is shared (a copied state, a batch's layered view) that fold copies all n entries.

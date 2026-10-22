# Some edits of long texts still cost a whole placement pass
> Summary: On a 100,000-character text, typing, deletes, moves and multi-edit commits now cost tens of µs, but a write that splits a range record (common on a text bootstrapped from a snapshot), a reset, or a move of elements caught in an earlier move cycle still costs a whole pass (~23 ms at 10^5) before the next read.
> Tags: performance, crdt

Repro: `cargo test --release -p osis-crdt --lib -- --ignored budget_big_text_spec_6 --nocapture` prints the times (notes/crdt.md Timing; received deltas go through encode and decode).

Remains:
- Fallbacks to a whole pass (full list in the `seq_lin` module doc): range-record splits (a write covering part of a state range record; splitting a row would need, for a creation chain, the rest of its subtree one level deeper, which `Placement::reshift` already does), resets, `Derived` dots, 256 or more newer siblings at one anchor; for moves also an element on a cycle a demotion broke (`Lin::cyc`) or a move closing a cycle, a written or dropped anchor that is unknown, `Derived` or inside a range record, and a sibling whose old write a move in the same delta pushed out of its top two.
- A received delta with more than max(√n, 64) runs and moves, or whose placements cost more than about a whole pass, rebuilds by design (hostile deltas then cost join plus one pass, about two passes at worst).
- `Batch` still copies the position's state where its records do not line up with the state's (the same range splits) or a reset of the batch lies above the position.
- List `read` looks up each visible element's record (text reads chars from the cache).
- A writer-side batch of thousands of moves on one text takes seconds (4000 moves: 4-8 s): each op clones the batch's net effect so far, and `Layered::present` clones the layer's records per op.
- The placement cache's dot map folds its added entries into its base past √n; when the base is shared (a copied state, a batch's layered view) that fold copies all n entries.

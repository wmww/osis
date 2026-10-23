# Some edits of long texts still cost a whole placement pass
> Summary: On a 100,000-character text, typing, deletes, moves, multi-edit commits and writes splitting a snapshot's range records cost tens of µs, but a reset (~11 ms pass after it), a move of elements caught in an earlier move cycle, and a received delete of most of the text (~1.5 µs per element) still cost a whole pass or more.
> Tags: performance, crdt

Repro: `cargo test --release -p osis-crdt --lib -- --ignored budget_big_text_spec_6 --nocapture` prints the times (notes/crdt.md Timing; received deltas go through encode and decode).

Remains:
- Fallbacks to a whole pass (full list in the `seq_lin` module doc): resets, a new `Derived` record or an anchor at an absent one (a virtual anchor), 256 or more newer siblings at one anchor; for moves also an element on a cycle a demotion broke (`Lin::cyc`) or a move closing a cycle, a written or dropped anchor that is unknown, a dropped anchor inside a range record, and a sibling whose old write a move in the same delta pushed out of its top two.
- Resets: a sequence reset re-anchors every element older than it on END, so any re-placement is O(n) for a `replace` or `remove_aspect`; the whole pass after one is cheap (11 ms at 10^5: every old edge is END, no lookups or cycles). Not worth a second placement path unless measured to matter.
- Moves on a broken cycle: following them needs which cycle forced each demotion (cycle groups, kept exact through every follow), a local §6.2 re-run from that group over the cached parents, and placement on END by dot: a second cycle breaker. Cycles need two or more concurrent moves of one range.
- A received delta with more than max(√n, 64) runs, moves and row cuts, or whose placements cost more than about a whole pass, rebuilds by design (hostile deltas then cost join plus one pass, about two passes at worst).
- A received delete of all of a 10^5 text (what `Set` of a new value sends) joins in ~155 ms: ~100 ms is the join itself (each element a piece joined on its own), ~55 ms following the flags (one record lookup and a block scan per element; flags are not counted in the work budget). Grouping flags by block would make the follow O(k log n + rows of the touched blocks).
- `Batch` still copies the position's state where its records do not line up with the state's (a write splitting a range record) or a reset of the batch lies above the position.
- A writer-side batch of thousands of moves on one text takes seconds (4000 moves: 4-8 s): each op clones the batch's net effect so far, and `Layered::present` clones the layer's records per op.
- The dot map is built eagerly with every rebuild (O(n) Dot clones, ~1.5 ms at 10^5, outside the work budget, like the pass itself), and its chunks split but never merge (at most n/64 chunks).
- Texts at a `Slots` position: a join that changes the register or raises the position's reset (an old app's save, a replace) re-embeds and prunes every member (O(n), drops the cache).

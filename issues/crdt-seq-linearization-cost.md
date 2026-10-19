# Sequence reads and ops re-linearize the whole state
> Summary: Every sequence read, index resolution and op places all elements from scratch (`linearize::place_idx`, O(n log n)), and a batch's second and later ops clone the aspect state; a 10^5-char text costs tens of ms per read or op. The incremental cache of notes/crdt.md (re-place touched subtrees, recompute an SCC on cycles) is not built.
> Tags: crdt

- Measured (`budget_big_text_spec_6`, release, 4 cores at load ~17): 10^5 chars in ~1000 runs: place 40 ms, read 37 ms, first op of a batch 62 ms, a two-op batch 176 ms, snapshot encode 84 ms, decode 129 ms; a one-element join 4 µs. Budgets of notes/crdt.md (sizes) are met; these are times.
- Cycle breaking is linear (persistent "reaches HEAD/END/hidden" mark): a chain of 20,000 plus 20,000 mutual-`cur` pairs whose victims walk into the chain places in 0.05 s release (was 2.4 s, quadratic); `cycle_breaking_is_linear_spec_6_2`.
- Shape of a fix: keep the chosen edge, sibling lists and order per `Seq` (or per node-core aspect), update them from the elements a join touches, fall back to a whole pass when a touched edge closes a cycle or a demoted element is involved; test it equal to `place_idx` on random histories. An order-statistic index makes index → dot O(log n).
- Batch clone: issues/crdt-path-op-cost.md; for text sessions a single `Op::Edit` per commit costs one pass instead of one per keystroke.

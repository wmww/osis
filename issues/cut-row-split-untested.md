# No default test reaches `cut_row`'s split on a paged state
> Summary: osis-crdt `seq_lin` `cut_row` (a write starting a row inside a placed row) is reached by no default crdt or engine test on a paged state: planting its cycle bail-out to always rebuild (`self.cyc.contains(&row.dot)` → `true`) failed nothing under `seq_` and `pages::tests::`.
> Priority: low
> Tags: tests, crdt

A plant sending every cut to the rebuild path changes cost, not the result, so the test that would catch it counts work: a paged state whose follow cuts a row, with the runs' work asserted near the cut's own (the rebuild walks the block's rows again).

Reaching a cut: a delete record plans a cut only against a record coarser than the rows, which needs the pages' range record (a stretch deleted in one commit); separate per-char records or a creation record do not (the state's records split where rows do). The follow's `runs/moves/cuts` counts show whether a try reached it.

# A cold commit's later ops and walk misses redo earlier follow work
> Summary: engine pages: a run on a sequence held in part stops at its first miss and runs again from scratch; misses found by dot come together (planned and looked up before a follow changes anything), but a commit's op j still misses only after ops 1..j-1 followed, and a walk (siblings past an anchor, a subtree's end) misses one per run, so k such misses cost about k runs of the work before them against the one-pass budget (`seq_cold_edits_keep_placement_plain` seed 47 step 139, an own two-op commit: "same delta as on the whole state").
> Priority: normal
> Tags: engine, crdt

`run_attached` / `pages::prefetch` run, load what the run missed, run again, until nothing is missed or the runs' summed work passes about one whole pass (notes/engine-paged.md, The work bound). `Lin::follow_in` and `seq::join_elems_in` note every by-dot miss of one follow before it changes anything, so a delta touching many far places takes a few cheap runs (`seq_far_apart_misses_found_together_spec_crdt_6_1`). Still sequential:
- a commit of several ops: each op's index resolves on the state its earlier ops made, so op j's misses come after ops 1..j-1's follows, repeated in each run; a commit of many far-apart costly ops can pass the budget and load whole;
- misses only a walk finds (`slot` past siblings, `past`/`end_of` into a stub block where a placement put the rows).

Seed 47 (debugging aid only): op 2's misses (a block, records, a chunk, a block, each found from the last) come after op 1's follow of about 976 units, which each run repeats: runs of 66, 66, 976, 976, 976, 2398 against a budget of 4147.

Directions, not yet weighed: keep a run's progress across loads (a stub block keeps its id and a stub chunk its first dot through a follow, so a followed placement can take the rows loaded later; the builder's fragment would need the loaded pages too); or load ahead for every op's index the blocks and chunks its range needs before the first run. Raising the budget is no fix (any constant fails at some k).

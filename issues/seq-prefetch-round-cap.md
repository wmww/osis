# A join drops a paged sequence's placement within its work budget
> Summary: `pages::prefetch` gives up after `PREFETCH` (8) dry runs even when the follow's work is far below its budget (about one pass), so a received concurrent move drops the stored placement (the next read by index rebuilds it); the work budget alone should bound it.
> Priority: low
> Tags: engine

Each dry run of the follow (`Fragment::dry_follow`) can reveal one more missing row, so a move into a region not loaded takes several rounds. `seq_cold_edits_keep_placement_spec_crdt_6_1` with its rngs at 0 meets a received move (len 2) plus insert into a 4000-char text needing 12 rounds at 1270 work of a 4024 budget: the round cap drops the placement and the test's "placement kept" fails at step 27 (with the cap lifted the test passes; most joins need under 8, a few 9-12). The test keeps its old rng seeds (187, 189) until this is settled.

Fix candidate: loop until no misses, the budget is spent, or a round loads nothing new (the progress guarantee the round cap stands in for), drop `PREFETCH` (notes/arbitrary-values-table.md, notes/engine-paged.md), and set the test's rngs to 0.

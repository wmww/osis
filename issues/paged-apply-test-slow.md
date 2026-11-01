# Paged-apply differential is too slow for tier 1
> Summary: `apply::tests_paged::paged_apply_matches_whole_spec_crdt_8` takes 12-18 CPU-s in tier 1 (rule: a few seconds); about 8 s is the final all-to-all sync re-delivering every held commit.
> Tags: tests, engine

Review of durable-apply: skipping commits the receiver already holds in that final sync cuts it to about 2.5 s, but may drop the late-part (pending, then applied) coverage; check that coverage survives (or move it into a smaller dedicated case) before cutting.

The `_large` twin has the same cost shape per seed: seed 265115 takes about 430-470 CPU-s alone (same on main at item 192 and after paged-failures) and passed the 600 CPU-s hung limit at load 40 in a 300-seed run (reported hung, not failing).

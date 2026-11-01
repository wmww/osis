# Paged-apply differential: one slow seed in the `_large` twin
> Summary: seed 265115 of `apply::tests_paged::paged_apply_matches_whole_large_spec_crdt_8` takes about 430-470 CPU-s alone, near the seed runner's 600 CPU-s hung limit.
> Tags: tests, engine

Seed 265115 takes about 430-470 CPU-s alone (same on main at item 192 and after paged-failures) and passed the 600 CPU-s hung limit at load 40 in a 300-seed run (reported hung, not failing). Not looked into: whether it is the history (many large fills) or a cost in the engine.

The tier-1 test is cheap since tier1-trim (seed 14 instead of 3: of seeds 0..32 at 14 steps the cheapest reaching all three asserted paths, 2.5x less CPU). The final all-to-all sync is not re-delivery waste: skipping deliveries the receiver holds byte for byte changed nothing measurable; its cost is applying the commits receivers lack.

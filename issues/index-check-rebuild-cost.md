# The end-of-history index check's rebuild cost
> Summary: The index check at each engine's drop rebuilds the index from the commit records, about 18% of the engine lib tests' instructions and most of what checking every history costs over the old sampling; a per-transaction check of only the index rows a transaction wrote, against a derivation of just those, would cost O(the change).
> Priority: low
> Tags: tests, engine

`Engine::check_index` at the end of every history (notes/test-harnesses.md, Debug checks) does an open from the persisted index (about 4% of the engine lib tests) and a rebuild from the commit records (about 18%: every commit judged again). The open half is cheap; the rebuild half is a second judging of the node's whole history per engine, so properties of many short multi-peer histories pay most (`deep_departure_holds` +34%, `nothing_before_a_cut_reaches_its_holder` +50%).

Cutting it by design means checking each transaction's index changes against a from-scratch derivation of just the rows it touched (per index table: which records each row derives from), so the check costs what the change did, with the whole rebuild kept for a reopen test. Not sampling: a check that skips short histories is what this replaced.

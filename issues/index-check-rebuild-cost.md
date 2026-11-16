# The end-of-history index check's rebuild cost
> Summary: The index check at each engine's drop rebuilds the index from the commit records, about 15% of the engine lib default tests' instructions and the most of what checking every history costs over the old sampling; checking only the rows each transaction wrote misses what the rebuild finds, so a cheaper check needs another design.
> Priority: low
> Tags: tests, engine

`Engine::check_index` at the end of every history (notes/test-harnesses.md, Debug checks) opens from the persisted index (about 5% of the engine lib default tests) and rebuilds from the commit records (about 15%: every commit judged again, its records and parts not decoded again). Against the sampled check it replaced, the engine lib default tests cost about 12% more, `it` about 9%, the engine properties about 4%.

The rebuild is a second judging of each engine's whole history. What it catches that the open does not is a row the incremental code should have written and did not (planted: an edit's place left out of `originals`, 37 tests against 16). A per-transaction check of the rows a transaction wrote is blind to exactly that (simulated with an exact from-scratch derivation per transaction: 17 of 37), so it is no replacement. A cheaper check that keeps the property needs one of:
- a per-record derivation: for each record a transaction touched, every row it derives, from that record alone, compared both ways (catches missing and stray rows of direct derivations; rows judged from other records, the arrival-order class the rebuild found, stay the rebuild's);
- the rebuild's own remaining cost cut: it opens every `secrets.0` box again (KEM opens) and decodes every state again (`observe_state`), about a third of what is left.

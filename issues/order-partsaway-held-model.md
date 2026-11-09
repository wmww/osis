# order: held-model reads a map field the node drops at `later`
> Summary: order::held_set_decides_plain fails on a PartsAway history at the `later` check: held-model reads a map field the node does not, in chronological order, on main too. Property: the read is a function of what is held; the model and the node disagree about a part. Find which is right (a part kept away while its commit's other part applied) and shrink to a small test.
> Priority: normal
> Tags: tests, engine

Not caused by the expiry-6 branch (fails on main at the same point). Reproduce with `tools/test_select.py --run` or the order harness at a random offset; shrink with `OSIS_ORDER_SHRINK=1`.

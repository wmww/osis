# sync-certs
- A `git add -A` commit swept a throwaway debug test (`links::zz_debug_redeem`) into a step commit; removed in the next. Keep probes out of the tree or commit by path.
- Load ran above 100 during the run: sync test timings (34 s vs 97 s) meant nothing.
- Engine tests encode "unjudgeable keeps nothing" in a dozen places (`Ingested::Awaits` asserts); changing the rule meant touching each by hand.

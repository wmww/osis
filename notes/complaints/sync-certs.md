# sync-certs
- A `git add -A` commit swept a throwaway debug test (`links::zz_debug_redeem`) into a step commit; removed in the next. Keep probes out of the tree or commit by path.
- Load ran above 100 during the run: sync test timings (34 s vs 97 s) meant nothing.
- Engine tests encode "unjudgeable keeps nothing" in a dozen places (`Ingested::Awaits` asserts); changing the rule meant touching each by hand.
- Review: `git checkout <file>` to undo a mutation probe also undid the uncommitted fix in that file; copy the file aside or commit first.
- Review: two engine tests fail on sync-rebuild itself (`order::kill_and_purge_in_one_commit_keeps_leftover`, `scale::purge_rejudge_is_linear_in_requests`, both known issues): a full engine run never comes back green.

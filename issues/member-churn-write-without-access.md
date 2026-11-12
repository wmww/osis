# member_churn: a node writes a thing it no longer has
> Summary: The sim's `member_churn` at seed 1527650006 fails at step 116 on main: node 5 commits on a thing it cannot write. The sim's choice of writer, or a node dropping access too early.
> Priority: normal
> Tags: tests, sim

`osis_sim::replay("member_churn", 1527650006, 1527650006)` (passes at main 066310a12: the seed came from an older harness): on main "no permission to write", on expiry-7 "unknown thing" at the same step. Found by the expiry-7 review; not caused by it.

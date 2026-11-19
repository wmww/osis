# pull-cursor review
> Summary: Footguns met reviewing the pull-cursor branch.

- A Pair test of "caught up waits for X" passes with X's rule disabled unless the frame that would end the wait (here b's join Pull) is held too: check each such test by disabling its rule.
- keep::readers_logging_the_same_records_settle_on_one_record_blob already takes ~8 s in debug (three world restarts), past the "few seconds" default-test budget.

# eph-churn-demote
- `OSIS_EPH_TRACE=<commit prefix>` misses arrivals (a blob not opened yet has commit `-`): trace by the blob prefix to see where a waiting entry came from.
- The churn oracle's step log and the trace are separate streams, so the order of lane events against steps (restarts, promotions) has to be guessed.
- Two seeds in 140000..140300 hang (on main too); the seed runner then kills the whole run at 600 s and no other seed's result is printed: a 300-seed run cost 11 min and told nothing until rerun around them.
- 3 of the 10 seeds in the brief were a different class (expired non-value writes), not the demotion one; diagnosing that took a temporary state dump in the engine.

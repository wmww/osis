# test-cuts
> Summary: Footguns met applying issues/test-consolidation.md's high-confidence entries.

- The issue's line numbers had drifted and several "high" claims were looser than stated ("exact prefix", "same world", "subset"): each needed both tests read, and a few asserts moved before a delete was safe.
- Whether a reopen runs `check_index` is not visible from the test helpers; a temporary `eprintln!` in `check_index` was the quickest way to know (it does not).

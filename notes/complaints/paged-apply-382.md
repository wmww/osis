# paged-apply-382
- The issue blamed the compaction trigger; the extra snapshot was a purge-on-replace cover in both worlds with different frontiers. The failure's own output could not show that: `tests_paged`'s `first_diff` prints the index digest as one line ("at line 0"), so finding the differing commit took a probe writing both digests split per commit and diffing them.

# paged-apply-382
- The issue blamed the compaction trigger; the extra snapshot was a purge-on-replace cover in both worlds with different frontiers. The failure's own output could not show that: `tests_paged`'s `first_diff` prints the index digest as one line ("at line 0"), so finding the differing commit took a probe writing both digests split per commit and diffing them.
- Review gate (load 28): `sources::a_move_ends_watches_of_the_group` timed out again (issues/sources-tests-flaky.md) and is not in known_failures.txt, so it shows NEW each time; it has no repro setting to list.

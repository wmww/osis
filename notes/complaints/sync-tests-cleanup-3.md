# sync-tests-cleanup-3
> Summary: The brief's profile was stale by 3x after test-cost-4; a world built in another order trips a tolerance count; a plausible plant for a merged test was caught by neither original.

- The brief ranked tests from pertest-264dc1a4c; on today's main the top sync tests cost a third of that (read's n/10n start test 142 G there, 50 G here; read:: 76 G as a module). Re-measure before ranking.
- Sharing one n-things world between idle and read first built all n things before the reconnects; idle's store-row tolerance (`4 * 16` rows) then failed by about 30 rows of per-input scans (`next wake`, `driver store`), not per member. A shared builder must replay the exact build order of the tolerance test it serves.
- The obvious plant for a "closes on a report" test (`close_if_reached` never closing) failed neither the original keep test nor its merge: the harness's quiet check (`sources_are_members`) is what catches the class, by a status plant (`Moved::Left` ignored). Find a plant the original fails before judging a merge by it.
- A fresh-vs-copy check needs a temporary patch of `harness::fixture_with` (no env switch): keep a copy of `mod.rs` in scratch and restore it.

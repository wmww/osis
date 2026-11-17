# keel-retention-tail
> Summary: Mishaps met on the retention tail branch.

- A scale test's `w.io.reads` read 0 for a forget (the store's cache serves the rows); `w.n("store rows read")` (the costs counter) is the one that counts scans.
- Two purge requests written in one test without a clock step build no commit ("no aspects"): the second `purge.0` write equals the first and is elided. `lp.advance(1)` between them.
- Many test helpers forged `created.0` with `KEPT_RETENTION` (`nobody`) only to skip delete keys; refusing `nobody` on mintings broke them. Their `Secrets` impls give an admin key, so the default retention works.

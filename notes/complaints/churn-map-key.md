# churn-map-key
- The issue's seed had gone stale before I started: it passed on the commit that filed it (11dc86ea9, after eph-reverts-seed merged) and failed only on the older effab1c91 the issue named. Finding that cost three bin-at builds. An issue filed for a seed should say the commit it was last seen failing at, and whether it was re-checked on main after a rebase.
- `tools/bin-at REV --patch` fails with only "no executable for osis-node --test it" when the patch does not compile at REV. The compile error is hidden; you have to rebuild by hand to see it.
- The churn harness prints node Tids that differ from run to run (cached world), so the commit and Tid names in the issue text could not be matched to a node index without adding tracing.
- A parallel branch (one-peer-3h1) fixed the same cause while this task ran, so my code fix was dropped. A known_failures line could name the branch working on it.

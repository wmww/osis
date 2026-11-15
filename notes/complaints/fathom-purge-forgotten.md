# fathom-purge-forgotten
- The brief named commit 7bb14aaec and the issue before the branch it was on reached origin (it landed as 9485a9dc5): a brief should name a pushed tip.
- `cargo test -p osis-engine --lib <filter>` relinks the whole lib test binary (about 3 min warm per planted fault); six faults cost ~20 min of builds.
- Two `LocalPeer::copy` runs draw different blinds, so commit IDs differ per run: a differential must keep IDs per run.
- Review: the index check (`testing::tables`) left out `forgotten_names`, so a new persisted index escapes the restart/rebuild check unless added by hand.

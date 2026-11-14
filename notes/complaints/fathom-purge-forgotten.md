# fathom-purge-forgotten
- The brief named commit 7bb14aaec and `issues/purge-by-commit-of-a-forgotten-commit.md` on capstan-sync-rebuild; neither exists in this repo or on origin. Worked from `Engine::forgettable` and the purge note as they stand.
- `cargo test -p osis-engine --lib <filter>` relinks the whole lib test binary (about 3 min warm per planted fault); six faults cost ~20 min of builds.
- Two `LocalPeer::copy` runs draw different blinds, so commit IDs differ per run: a differential must keep IDs per run.

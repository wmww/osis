# eph-revert
- The issue's "8 of 200 seeds" was stale: 38 of 200 failed on the branch point, most of them the undo reset not travelling. The named seeds were a subset.
- The session's start directory (wt7) was removed while I worked; `wt claim` had printed wt4, so only a getcwd error showed. Absolute paths and `cd` per call kept it harmless.

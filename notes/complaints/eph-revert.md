# eph-revert
- The issue's "8 of 200 seeds" was stale: 38 of 200 failed on the branch point, most of them the undo reset not travelling. The named seeds were a subset.
- The session's start directory (wt7) was removed while I worked; `wt claim` had printed wt4, so only a getcwd error showed. Absolute paths and `cd` per call kept it harmless.
- Review: the oracle's default 0..200 hides the listed failures (first at 435, 903, 911, 41169); one wider run costs under a minute, so a branch adding a skip to an oracle should widen it once and print what it skips.

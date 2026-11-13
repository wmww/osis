# eph-void-index
- `wt claim` printed wt12 while the session's environment named wt10 as the working directory; easy to build in the wrong tree.
- The property's restart seeds (`seed ^ step ^ 0x77` / `0x79` in `revert_run_with`) collide for steps 14 apart, so a node can reopen with its earlier open's rng and session nonce: that is how this seed reached overlapping counters. Harmless (it tests a real case) but surprising when reading a failure.

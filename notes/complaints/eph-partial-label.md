# eph-partial-label
- The repro test timed 5.3 s at load 34 (other agents) and 1.2 s a minute later: a tier-1 timing judged on a loaded box is noise; check `uptime` before calling a test slow.
- The first repro passed on unfixed code because a forced `compact_ephemeral_now` after the release re-covered and healed the loss: check the invariant before any later forced compaction.

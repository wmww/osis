# sim-work-sets
- A sim "read differently at quiescence" failure prints only the first differing read, held commit IDs and verdicts. Finding the cause needed throwaway debug code: per node the aspect state, `rebuild_state` result, each held commit's parts (missing/dropped/valid) and a per-step state-change trace. A divergence dump of the aspect's held parts and states (gated on `OSIS_SIM_TRACE`) would have saved most of an hour.
- `tools/wt claim` printed `.worktrees/wt2` while the session's primary directory was wt1; easy to run commands in the wrong tree.

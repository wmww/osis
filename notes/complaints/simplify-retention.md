# simplify-retention
- Tier 1 piped through grep, with a rebuild of osis-engine's dependents, passed the 2-minute foreground limit and went to the background mid-run; use `run_in_background` from the start after a crate-wide change.
- Issues and notes cite `file:line` (retention/mod.rs:550 and the like): a file split leaves them stale. Function names age better.

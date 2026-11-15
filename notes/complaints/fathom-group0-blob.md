# fathom-group0-blob
- The test harness captures stderr: a probe's `eprintln!` in `World::run` printed nothing until `-- --nocapture` (one wasted 3 min suite run).
- Read's verdicts have no test accessor on `Node`; a probe needs a temporary `#[doc(hidden)] fn verdict` in core/sync/src/driver/mod.rs.
- The brief's case ("node 1 lists a group.0 commit with no blob") was a claim its own review had already failed to reproduce (issue history, 483d21c90); a brief built on an unreproduced line costs a whole investigation.

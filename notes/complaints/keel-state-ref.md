# keel-state-ref
- `eprintln!` probes in engine tests show nothing without `-- --nocapture`; a first probe run looked like "never hit" until rerun.
- `engine_agrees_with_custody_model_large_spec_permissions_5_4` failed at gate size on the base I claimed (e.g. OSIS_CUSTODY_START=150045640141) with no known_failures line; cost a revert-and-replay to rule out this branch before main's issue (custody-differential-main-regression) landed.
- Checking out older sources mid-run of a background `cargo test` risks the run building the wrong tree; run comparisons only when nothing else builds in the worktree.

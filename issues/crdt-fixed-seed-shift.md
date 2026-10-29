# A crdt test's fixed seeds shift with OSIS_CRDT_SEED
> Summary: `tests_seq::derived_dots_follow_cache_spec_7` draws its "fixed seeds" through `testutil::rng`, so a tier-2 `OSIS_CRDT_SEED` (e.g. 973451) shifts them and its threshold check (2 < 20) fails on main; fixed-seed tests should not read the env seed. Also: the periodic `--include-ignored` crdt run always lists the known ignored repros as failures, so the periodic script should skip them by name.
> Tags: tests, crdt

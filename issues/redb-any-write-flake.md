# The redb any-write fault test fails now and then
> Summary: osis-store `store::a_failed_redb_write_anywhere_in_a_commit_reports_its_outcome` fails about 1 run in 20, alone or in the gate, on main: "faults both before the commit point and at its sync" (store.rs, the `failed && lost` assert): some runs see no write whose fault leaves the outcome unknown.
> Priority: normal
> Tags: tests, store

- Seen in the history-cut-3 review gate (TLA-only branch) and in 2 of 23 runs alone (`cargo test -p osis-store --test it store::a_failed_redb_write_anywhere`), at 0.08-0.2 s each.
- The test counts file writes with `FileDevice::trap` (tests/it/common/mod.rs) and expects one fault point to hit redb's sync; the count of file writes per commit, or which of them precede the sync, seems to vary between runs (a redb background or timing-dependent write, or state left by the previous iteration's recovery). Find the varying write, then make the test find the sync fault point by what happened (the sync trap) rather than by a write count, or assert the property per fault point without requiring each kind to occur.

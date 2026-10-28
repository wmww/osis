# crdt-simplify
> Summary: Workflow notes from the osis-crdt review-and-simplify pass.

- `tools/wt claim` found wt1's target at 15 GB (stacked generations) and deleted it; the first `cargo test -p osis-crdt` was cold (about 50 s, fine for one crate).
- Finding dead public API took a script: rustc's dead-code lint does not see `pub` items no other crate calls, so unused API (`Fragment::placement`, `struct_skeleton`, the per-author un-merge) sat unnoticed. `grep -w <fn>` over `git ls-files '*.rs'` outside the crate per public fn worked.
- `claudewait ID` on a background command of the form `uptime; for ...; done > file; uptime` printed "exit code unknown after 0s, finished earlier" at once, three times, while the loop was still running; I had to wait for the task notification instead.
- Release A/B timings of `budget_big_*` swing 2-3x between runs at load 5-11; only alternating copies of the two test binaries (`cargo test --release --no-run`, copy `target/release/deps/osis_crdt-*`) gave comparable numbers.
- Reviewer: `OSIS_CRDT_SEED=52007` failed `slots_join_follows_cache_spec_7` on main too: a sample floor (15 joins over 6 histories) some seeds miss. Fixed with 12 histories; other seeded tests with count floors may have the same weakness.
- Reviewer gate took 679 s at load 18-30: `clippy-net` was cold (298 s; the claim's target wipe only rebuilt the plain profile) and tier 1 rebuilt after the rebase (317 s).

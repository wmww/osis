# link-aspect
- First `cargo build -p osis` / `cargo test -p osis-node` in the claimed worktree each took about 3 min (cold-ish after a crdt/schema change: everything above rebuilds). Expected, but the 120 s Bash cap moved most calls to the background.
- Footgun met: a local engine commit verifies its own parts too, so a hostile-writer test needs `core.skip_writer_rules = true` around the commit; the first error (`Commit(Malformed)`) looked like a test bug.
- A bad part on a synced thing stalls its whole commit, the thing's other parts included (spec/commits.md §4): a test that expects the commit's other part to show must put it on another thing.
- Review: the full core-aspect type check broke 21 tier-1 tests that used ill-typed core values as handy test data (`name.0 = Int`, a string in `roles.0`, secrets bytes on `label.0`, AnyView-written structs); a hostile-input test should pick a well-typed carrier unless types are its subject.
- Review: `cargo test --workspace` stops at the first failing crate; use `--no-fail-fast` to see every failure in one 7-11 min run under load.

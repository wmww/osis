# reset-redates
> Summary: Footguns met while making `ByWrite::moved_by` read only what came since a write's floor.

- The issue file named in the brief was on an unmerged branch (`git show origin/mizzen-rows-exact:issues/...` found it).
- A `cargo test --list` run to look up ignored names rebuilt the whole engine after a file restore (8 min): list from the already-built `target/debug/deps/<crate>-<hash>` binary instead.
- `cargo test -p <crate> --lib -- --ignored retention::` also picks a `_large` and a by-hand test: list first, then pass `--exact` names.

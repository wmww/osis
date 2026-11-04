# until-drop
> Summary: workflow notes from the until-drop worker (fable).

- The backed-out attempt (commit db20726a) was the best reading material: its diff shows the three scopes, `heard_out`, `lost_by_time` and the removed tests, which the issue only names. A brief could point at the back-out commit directly.
- `wt` and `claudewait` were not on PATH; the plugin cache paths from notes/coordination.md worked.
- The osis `EdgeOpts` has no `keep` any more (the removed tests used it); keep is the thing's default now (`set_keep_default`). Took a build to find out.
- First targeted test build (node + osis test binaries) took about 5 min on a warm worktree; the second one about the same, so plan two test rounds at most before tier 1.
- I ran a python edit script inside a `run_in_background` command and never read its output: an assertion failed on the first file, nothing was written, and the next test run tested the wrong tree (two failures looked like design problems). Scripted multi-file edits go in a foreground call whose output is read, then the build goes to the background.
- `cargo run --bin sim-sweep` with no arguments is 100 seeds per scenario (periodic-sized, about an hour at load 25): I stopped it after 12 minutes and ran the gate's `--seeds 5`. A brief saying "run the sim-sweep" should give the seed count.

Reviewer (fable):
- The rebase hit a conflict in notes/core-triage.md only (abs-keep's row 4 beside this branch's row 3); local main lagged origin/main by one notes commit, so two rebases.
- `cargo test -p A -p B --no-run` prints one `Executable` line per crate and the `it` hashes look alike: I copied osis-perm's `it` as the node's once. `cargo test -p <crate> --test it --no-run | grep -o 'target/debug/deps/it-[0-9a-f]*'` per crate is the safe way to find each.

# mid-simplify
> Summary: Complaints from the label/commit/keys simplify pass.

- Load 26-35 from other agents' oracles: `cargo test -p osis-keys` (one small crate) took 12 min, the warm `cargo test --workspace` well over 10; every cargo was SCHED_IDLE (notes/build.md). Most of the task's wall time was waiting.
- Splitting one worktree's changes into focused commits without `git stash` or `git add -p`: staged an intermediate file version with `git hash-object -w` + `git update-index --cacheinfo`, which leaves the worktree untouched (safe while a build runs). Worth a line in notes/build.md if others hit it.
- `Option<&mut dyn Trait>::as_deref_mut()` in a loop fails borrowck where the hand-written reborrow `match &mut x { Some(p) => Some(&mut **p), None => None }` works (dyn lifetime under `&mut`): not a simplification to retry.
- Review: load 30-46; warm `cargo test --workspace` took 7 min, the 30-seed sweep 403 s.

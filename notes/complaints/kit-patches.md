# kit-patches complaints
> Summary: footguns met vendoring masonry_core and adding masonry_winit hooks.

- A vendored path crate is "local" to cargo, so its upstream warnings print on every build (masonry_core: 6 under this rustc); silenced in its Cargo.toml `[lints.rust]`.
- Writing a per-fix .diff against upstream when another patch touches the same file: diff the pre-change copy, `patch` that onto a pristine upstream copy, diff again. A snapshot of the vendored dir before editing saves redoing it.
- kit/tests can drive a headless `RenderRoot` directly (no `masonry_testing`, which is not in the lock).
- Released the worktree before the ff-merge; main had moved, so the merge failed and the worktree had to be reclaimed (got a different one). Release only after main holds the commit.

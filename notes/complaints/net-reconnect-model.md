# net-reconnect-model
> Summary: Mishaps on the reconnect model branch.

- tools/heavy is on main only; a fresh worktree branch from an older commit lacks it until `git rebase main`.
- TLC 2.19 has no ALIAS in the cfg here, so a counterexample is a screen of full records; a small trace printer per model is worth writing first.

# disputes
- `tools/bin-at` checks main out in the worktree, so docs edits had to wait the whole release build of two crates (11 min at load 20): a flag to build from a `git worktree add --detach` copy sharing the target dir would free the worktree meanwhile.
- The model's `edges::random_shaped` gave the first admin a genesis edge with invite admin while the world maps it to the record edge (no invite): invisible to the existing differential (it skips the first admin's ops), it showed only as a dispute mismatch. Model genesis now matches the record edge.
- Running `./target/release/roles-model` with no arguments starts the 2M-sample `single` search (a minute of CPU): a `--help` or a required mode would be kinder.

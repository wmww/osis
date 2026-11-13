# fsync-landed
- The first version of the power-cut test committed again after the faulted commit before cutting the power; that commit rewrote the same table page and made the lost write durable again, so the test passed without the fix. Cut the power straight after the faulted commit, and check the test fails with the fix turned off.
- `cargo clippy --all-targets` took over 2 minutes in a warm worktree and went to the background.

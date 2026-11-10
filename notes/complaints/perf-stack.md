# perf-stack
> Summary: Footguns met reviewing and stacking one-workspace, build-speed and test-audit.
- A mutation that makes judgment order-dependent trips the engine's reopen check ("opened from the persisted index: judged anew") in a test using `Peer::fork` before the test's own assertions run: read the panic site before crediting a test with a catch.
- Box at load 25-60: the derived set took 29 min (21.5 min held), the gate 1624 s, 12 min of it waiting on the heavy lock behind another branch's oracle runs.
- `cargo tree` diffs over a source-only copy of the tree (`git ls-files` into the scratchpad) check each feature pin's need in seconds per pin, without touching the worktree's build.

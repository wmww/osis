# addenda-model
- The roles-model digest values in notes/testing.md were stale for the current toolchain (main's code gives different hashes); checking "role layer unchanged" needed a rebuild of main's sources in the worktree (wip commit, `git checkout main -- src`, digest, restore). Updated the values.
- No roles-model README exists; the lib.rs doc comment serves as one.
- `addenda-exh` runs 2.83M worlds with five body simulations each: 11 min wall on 16 threads.

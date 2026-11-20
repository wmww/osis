# a1-paths
- `git push --force-with-lease origin HEAD~1:windlass-a1-paths` fails for a branch not yet on the remote ("did you mean refs/heads/..."): the first push needs `HEAD~1:refs/heads/<branch>` and no lease.
- `tools/heavy` held a four-crate test run 10 minutes behind another all-core run; the run itself took 3. A worker's per-crate checks under heavy wait as long as any gate.
- Forcing a wire form across the suites (`hashed_through` by default) is the fastest way to find what a form breaks: 1066 failures at first, nearly all one rebuild-check mismatch; worth a documented switch rather than a constructor edit on a wip commit.

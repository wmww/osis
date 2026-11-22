# engine-it-tests-4
- A rebase that brings source changes (main's crdt edit here) voids a baseline binary copied before it: the per-commit before/after needs `tools/bin-at origin/main` again after every rebase, which leaves the tree detached while it builds (read the branch with `git show`).
- A fresh-vs-copy check for scale tests is cheap and exact: every printed count (`flat`/`linear` lines) of a `--nocapture` run compared sorted between main's binary and the branch's. A cached world that changed any count shows there before any assertion moves.

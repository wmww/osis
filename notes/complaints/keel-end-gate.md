# keel-end-gate
> Summary: Mishaps running the reference graph's end gate.

- On a branch equal to origin/main the gate selects nothing; `--all` is needed for the end gate.
- Every stage ran at load 21-24 beside other agents' unlocked builds and tests and blew its time cap (whole gate 767/299 s); the limits say little about the tree under that load.
- Bisecting a property seed costs ~2 min per revision in one worktree (rebuild of osis-engine lib tests).

# sheave-r17-chain
- tools/mutate.py refused itself: after a batch with a mutation that does not build it calls
  `main` again for the rest, which took the worktree lock a second time (a second flock in one
  process) and exited "another tools/mutate.py runs". The batch's results were lost and the run
  had to be redone. Fixed: a held lock is kept. A test of the rebuild path would have caught it.

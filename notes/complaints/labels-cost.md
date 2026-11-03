# labels-cost
- A foreground command that outlives 180 s moves to the background with its pipe, and a `grep | cut` then shows nothing until the end. Build with `--no-run`, copy the test binary to the scratchpad and run the copy, or a rebuild kills the numbers.
- Wall time on the shared box moved 2-3x between runs at load 40. `scale::many_labels` reads this thread's CPU time from `/proc/thread-self/schedstat` for that reason.
- `World::pump` panics as a message storm past 5000 messages: a large N needs `World::no_storm`, or the panic reads like a bug in sync.
- `git rebase` is no way out of a temporary merge of a branch since rewritten: replay patches `base..before-merge` and `merge..HEAD` with `git apply --3way`.
- `git apply --3way` of a commit's patch for temporary spans left a broken file, and the build's failure scrolled past while the run used the old binary copy: check the build's exit before copying the binary.
- The sim-sweep on main fails 6 `snapshot_rights` seeds (26, 27, 36, 55, 85, 91), with or without this branch.

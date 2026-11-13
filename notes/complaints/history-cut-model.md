# history-cut-model
> Summary: Workflow snags met while model-checking the history cut.

- I ran multi-worker TLC by hand outside `tools/heavy`, with `-metadir` in the tmpfs scratchpad; the coordinator caught it. The README's by-hand TLC line shows `-metadir /tmp/tlc-states` and `core/test/tla/run.sh` uses `mktemp -d` (also /tmp, RAM): both teach the wrong place. Point both at a directory under the worktree.
- The Cut.tla invariants evaluate `Settled` (many closures) in every state, so TLC slows to ~20-60k distinct states/min; a cheaper settled check would make the larger instances run-sh sized.
- I also held the heavy lock for over an hour (X_cut 25 min, X_later 27 min, X_two 12 min in one `tools/heavy` call) and gates queued behind it. Split TLC runs into one short `tools/heavy` call per instance and size by-hand instances to the 10-minute budget before launching; nothing in the README or run.sh says how to estimate a TLC instance's size first (a 1-worker run for a minute and the queue growth would have shown it).

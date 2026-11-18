# keel-diff-rest6
- The issue said 189 had an 8-step shrunk script; it was not in the file, so the shrink ran again (about 15 minutes).
- A background `tools/heavy cargo test -p osis-engine -p osis` waited 9 minutes for the lock and then built from the tree as it stood when the lock came, not when the command was typed: I had reverted an experiment in between, so the run tested the wrong code. Copy the test binary first (as done for the differential holds), or keep the tree still until the build starts.
- Shrinks with `OSIS_SHRINK_MATCH` over 5 seeds in parallel take 15+ minutes each and stop at the 600 CPU-s seed timeout (131 at 15 steps); replaying the partial script over 30 worlds was the faster check.
- `git stash list` is blocked by the permission layer (fine: CLAUDE.md forbids stash), but a rebase then needs the scratch `mod scratch;` line reverted by hand first.

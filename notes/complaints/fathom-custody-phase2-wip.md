# fathom-custody-phase2-wip
- Bisecting one osis-sync test across this branch's commits meant checking out each commit in the task worktree and rebuilding engine + sync (about 4 min each); an uncommitted debug edit made the checkout abort silently inside a background chain.
- The sync harness's must-hold check names a commit ID only; finding which thing and part it is took three rounds of temporary debug prints.
- `World::run` asserts the must-hold checks at quiet, so a debug test cannot look at the failing state after it; stepping with `step_or_wake` in a loop was the way in. No helper prints a commit's `secrets.0` boxes (holder, role, epoch): parsing the fragment's Debug text was.

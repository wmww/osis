# fathom-custody-phase2-wip
- Bisecting one osis-sync test across this branch's commits meant checking out each commit in the task worktree and rebuilding engine + sync (about 4 min each); an uncommitted debug edit made the checkout abort silently inside a background chain.
- The sync harness's must-hold check names a commit ID only; finding which thing and part it is took three rounds of temporary debug prints.

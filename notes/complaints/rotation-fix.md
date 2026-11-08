# rotation-fix
- `wt claim rotation-fix` made the branch from main; the brief wanted it from `rotation-gen`, so it took a `git reset --hard rotation-gen` in the worktree before rebasing.
- Debug prints in `apply/` or `engine/` rebuild most of osis-engine (about 4 min a round); prints in the test module alone rebuild in under a minute. Root-causing went faster once the dumps lived in the test.
- No test-side way to ask why a part is invalid (which rule failed): a temporary `validity::dbg_part` did it. A `Engine::why_invalid(commit, part)` test helper would have saved two rebuilds.

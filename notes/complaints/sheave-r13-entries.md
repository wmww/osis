# sheave-r13-entries
- Two agents in one worktree share one git index: a notes worker's `git rm` (staged) landed in the code worker's commit, though each limited its `git add` to its own paths. Prevention: briefs for parallel agents in one tree say `git commit <paths>` (or `git rm --cached` never), not `git add` then `git commit`; or each agent gets its own worktree.

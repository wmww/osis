# vouch-cost
- Splitting one restructure into per-piece green commits by hand (save the later state, rebuild the earlier one with reverse edits) cost more than the pieces; pieces sharing files would be cheaper to brief as one commit with per-piece count tests.
- `git diff --stat` after a `reset --soft` of a local wip commit shows only unstaged files: use `git diff HEAD --stat`.

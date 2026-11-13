# cleanup-commit
- The session started with its cwd in wt9 (the commit-cost worktree, still on that branch); `wt claim` gave wt12. Easy to edit the wrong tree when the start dir is someone else's worktree.
- A 3-line edit in osis-node (dropping a redundant `is_*_blob` check) costs `cargo test -p osis-node` plus `-p osis --test it`: about 8 min wall.

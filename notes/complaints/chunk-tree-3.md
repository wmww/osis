# chunk-tree-3
- `tools/test_select.py --base main` lists main's own newer paths when the worktree branch is behind main (it diffs against main, not the merge base): read it after a rebase.
- Ephemeral tests reading a commit's pages or tree still go through `header.chunks` (about 15 tests): step 4 must rewrite them against `Engine::live_trees`/`blob_wants` or the writer's blob lists.

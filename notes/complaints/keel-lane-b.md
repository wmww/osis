# keel-lane-b
- Store table reads (`table_range`, `table_get`) stamp the whole table, so a memo or `Effects` key reading one reference row moves with every reference write; the closure had to take row changes from `refs::note` instead. Nothing says so where the reads are; it cost a rewrite of the edge follower.
- A full build after a rebase onto another lane's wide change runs 3-7 minutes; each crate test run rebuilds test binaries again. Batching edits before builds matters more than usual here.
- A wip commit made to rebase across a conflict stayed in the branch and had to be squashed by `reset --soft HEAD~2` after the rebase: commit with the real message before rebasing.

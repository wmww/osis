# keel-diff-five
- `deletes::a_new_reader_of_a_cover_stripped_commit_misses_nothing_spec_commits_5` fails on main from 45975c07b (account-level own cover), checked in a worktree at that commit; my first push went out after only engine tests on the rebase (sync untouched by main, but sync depends on engine). Rebases that move engine should rerun the sync `it` binary too.
- A shrunk script that passes on a hand-built world can hide on key order: two writes at one manual-clock ms order by node and commit, so a hand test of "a removal after a grant" needs `w.advance` between them.

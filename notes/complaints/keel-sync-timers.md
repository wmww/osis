# keel-sync-timers
> Summary: Mishaps met on the timer rule (Mono clock) branch.

- Removing unused `let now` lines found by compiler warnings: a loop rebuilding `-p osis-engine --all-targets` once per warning took 13 min; delete them all from one warning list, highest line first per file.
- The fixture guard ("a second live copy in one test") forbids looping one test over two worlds from the same fixture: write one test per case with a shared helper.
- `origin/main` is shared by every worktree: another agent's fetch moved it between my rebase and a squash, so `git diff --cached origin/main` showed main's newer commits as reverted. Squash with `git reset --soft HEAD~N` counted from the rebase, then compare against the rebase's base.
- `deletes::a_new_reader_of_a_cover_stripped_commit_misses_nothing_spec_commits_5` fails on origin/main (e8aaa1b03) alone.

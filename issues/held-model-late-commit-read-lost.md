# held-model: a late commit loses a read the full history keeps
> Summary: `props::late_commit_converges_after_repair_large_spec_commits_5` fails on main at seed 527365123558: settling the history without one commit, then with it, never reads thing 13's aspect 3 (`Str("e")`) that settling the full history reads; a model or generator case of spec/commits.md §5 to find and turn into a hand test.
> Priority: normal
> Tags: tests, held-model

- Replay: `OSIS_HELD_START=527365123558 OSIS_HELD_SEEDS=1 cargo test -p held-model --test it -- --ignored --exact props::late_commit_converges_after_repair_large_spec_commits_5` (fails on f5bcabb26 and on e1a312a2a, before 026decfa4's cover lifetimes). Listed in tools/known_failures.txt.
- The late commit: id 191086, Content by 3, a register write on thing 13 aspect 9. Every other read and the signal history agree; only `(13, aspect 3)` differs (`reads_off` after repair: absent; full: `Str("e")`). Seeds move when the generator changes: shrink to a hand-built history first.

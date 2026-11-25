# held-model: forced fates change a read at seed 651160929523
> Summary: `props::settled_histories_keep_their_laws_large_*` and `props::late_commit_converges_after_repair_large_*` fail on main at held-model seed 651160929523, round 0: the drops and strips the fates force (with their covers) change a read (a read of thing 10 present before is gone after).
> Priority: normal
> Tags: tests, held-model

- Replay: `OSIS_HELD_START=651160929523 OSIS_HELD_SEEDS=1 cargo test -p held-model --test it -- --ignored --exact props::settled_histories_keep_their_laws_large_spec_commits_5` (and `late_commit_converges_after_repair_large_*`); panics at tests/it/props.rs "forced fates changed a read".
- Seen: thing 10's aspect 12 (a map) read before the forced fates, absent after; the other reads equal.

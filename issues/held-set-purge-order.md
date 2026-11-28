# held_set_decides: a purge history judged differently by what was held
> Summary: osis-engine `order::held_set_decides_plain` fails on main at a gate seed (Purges emphasis): one held set reads a later message than the model after purges by author and by ID; not shrunk.
> Priority: normal
> Tags: engine, tests

Found by a gate on main (fails on the merge base alike, so no branch's change). Replay: `OSIS_ORDER_SEED=851492042192 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (`want Ok(Some(Str("m5")))`, `got Ok(Some(Str("m8")))`); `OSIS_ORDER_SHRINK=1` shrinks it. The history opens with a signal and messages by peers 1 and 2 on thing 0, then `PurgeAuthor { by: 0, t: 0, of: 1 }` and `Purge { by: 0, t: 0, of: 2, .. }`: start the study from spec/commits.md §5 (purges) and notes/purge-model.md. Seeds move with the harness: work from the shrunk script, then a hand test.

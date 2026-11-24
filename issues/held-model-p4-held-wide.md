# held-model's wide gap worlds fail P4-held at some seeds
> Summary: held-model `spec_gaps::evidence_reach_and_generator_gaps_large` fails 2 of 240 worlds from seed 662818812978 (first `a2 wide Wide { split: false, late: false, mint: false } 662818812993`, P4-held at step 23). Cause not read; suspect 95aa4c73d (a creation chained only over writes before its naming write): bisect first, then a hand-written reproducer.
> Priority: normal
> Tags: tests, held-model

Replay: `OSIS_HELD_START=662818812978 cargo test -p held-model --test it -- --ignored --exact spec_gaps::evidence_reach_and_generator_gaps_large`.
One world: `OSIS_GAPS_SEED=662818812993 cargo test -p held-model --test it -- --ignored --exact --nocapture spec_gaps::gaps_show` prints P4-held at step 23 (stages a2 and a2-actor, commits 1 and 19 of sync ID 12).

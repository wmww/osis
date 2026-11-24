# held-model's wide gap worlds fail P4-held at some seeds
> Summary: held-model `spec_gaps::evidence_reach_and_generator_gaps_large` fails 2 of 240 worlds from seed 662818812978 on main (6ec4ac443): first `a2 wide Wide { split: false, late: false, mint: false } 662818812993`, P4-held at step 23. Seen at the roles-held gate (renames only, no held-model change). Suspect: 95aa4c73d (a creation chained only over writes before its naming write) — bisect first. Cause not read.
> Priority: normal
> Tags: tests

Replay: `OSIS_HELD_START=662818812978 cargo test -p held-model --test it -- --ignored --exact spec_gaps::evidence_reach_and_generator_gaps_large`.
One world: `OSIS_GAPS_SEED=662818812993 cargo test -p held-model --test it -- --ignored --exact --nocapture spec_gaps::gaps_show` prints P4-held at step 23 on main (stages a2 and a2-actor, commits 1 and 19 of sync ID 12).

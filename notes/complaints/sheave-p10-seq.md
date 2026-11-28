# sheave-p10-seq
> Summary: The engine's seq cold-edit property has no shrinker; a by-hand ddmin over its steps took 40+ min for 148 -> 122 steps.

- `engine::pages::tests::seq_cold_edits_keep_placement_plain_spec_crdt_6_1` has no shrink hook. A throwaway ddmin (record each step's rng draws, skip steps, keep the failure's own assertion) replays every candidate from step 0 at ~5 s each: 40+ min reached 122 of 148 steps. Probing the follow's give-up sites found the cause in minutes. What would help: a step-skip hook in `seq_cold_edits` plus `OSIS_SEQ_COLD_SHRINK`, or a note that for a placement give-up, probing the `false` returns of `Lin::plan`/`follow` beats shrinking.
- World `run` jumps to every wake within `HORIZON_MS` (an hour), so a commit waiting for `Drift` (`MAX_DRIFT`, also an hour) is applied inside the same `run`. A test of a waiting commit needs `w.horizon_ms` lowered; notes/test-harnesses.md could say so.

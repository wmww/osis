# m1-until
> Summary: Workflow notes from modelling an end date on admin as a lowering (roles-model `paths`, finding 38).

- The brief expected an end date as a lowering to close findings 35 and 36. A two-line hand check (36's world with a removal in place of the end date) shows the same unshown effect, so the class never turned on the end date; worth running such a check before a model item is briefed.
- `tiny_world` picked its trusted lowering from the rule's own set of lowerings, so widening that set changed which worlds were trusted and made before/after counts incomparable; the pick is now by `World::lowers` alone.
- Story counts before and after a change to the thief's moves are not comparable (`rng.below(MOVES)` reshuffles every random world): the rule change was measured on a binary built before the moves were added, copied to the scratch dir and run under `tools/heavy`.
- `cargo test -p roles-model --lib paths -- name --ignored` runs every ignored test matching either filter (all the `repro_*`); put the one filter after `--`.

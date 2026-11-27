# sheave-c28-owners
> Summary: a count test's numbers moved with the tests run beside it and nothing said why; finding where read's work grew took many by-hand dumps.

- `growth::declined_grants_cost_*` counts 336 judgements in round 8 beside the other growth tests, 330 alone, the same every time. Ruled out by hand, one build each: skips (`OSIS_QUIET_MISS=1`), `world_of`'s copy order, which thread built the fixture. notes/engine.md says this cannot happen. What would have helped: a harness switch that runs a count test twice in one process (alone, then after its neighbours) and diffs every counter, naming the first that differs.
- To find which rows or bodies grew per round I patched `eprintln!`s and `costs::by_caller` into growth.rs, judge.rs and live.rs several times. What would have helped: a by-hand `growth::` probe printing every counter per round for an arm, the growing ones first (like `idle::probe_counts`).

# held-model arrival orders read unlike at seed 92
> Summary: held-model `props::arrival_orders_read_alike_after_repair_large_spec_commits_5` fails at seed 92 (full size, seeds 0..300): after one-at-a-time arrival (order 0) thing 10's aspects 1 and 2 read none where the settled full set reads `Str("")` and `Map{1: 0}`; both writes are held but judged `MustDrop(Unknown)`, beside a Content commit whose body is `Missing`. Cause not studied.
> Priority: normal
> Tags: held-model, tests

Replay: `OSIS_HELD_START=92 OSIS_HELD_SEEDS=1 cargo test -p held-model --test it -- --ignored props::arrival_orders_read_alike_after_repair_large_spec_commits_5`. Listed in tools/known_failures.txt (rate). No shrinker for held-model props.

First failing line: `seed 92 order 0: [((10, Aspect { name: 1, .. }), None, Some(Str(""))), ((10, Aspect { name: 2, .. }), None, Some(Map([(Int(1), Int(0))])))]`. The bodies on those aspects in the arrival-order node:
- 859521 Content, AuthorOrAdmin, body `Missing`, valid
- 272257 Content, AuthorOrAdmin, Register `Str("")`, fate `MustDrop(Unknown)`
- 543650 Content, Admin, Map entry `1 -> 0`, fate `MustDrop(Unknown)`

So the arrival-order node judges the two writes unknown (waiting on something it never fetches again) where the full set judges them valid: likely a fetch-again case `settle` misses (`Outcome::uncovered`/`revisit`/`NeverReceived`) or a model judgment depending on arrival. Fix with a hand-written reproducer (notes/principles.md, Never pin a seed).

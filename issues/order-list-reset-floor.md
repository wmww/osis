# held_set_decides_plain misses its list-reset coverage floor
> Summary: `order::held_set_decides_plain` fails its coverage floor on main at random offsets: its Settled-emphasis seeds ran, but held-model judged no "list write above its reset" (`held::REMOVALS`), so the generator no longer reaches a write in a list element above that element's reset within 8 seeds.
> Priority: normal
> Tags: tests, engine

- Seen in two `--all` gates on main (offsets 915278718338 and 988856941855, 1c7d769c0 and 4ad05292b): `held_set_decides: Settled seeds ran, but held-model judged no list write above its reset` (`Seen::floors`); every history passed its checks.
- Either the generator's `Settled` emphasis (`order.rs`, the step writing into an element above its reset) stopped producing it after a later step change, or the held-model tally stopped counting it. Find which with `OSIS_ORDER_STATS=1` at one of those offsets; a floor met by too few seeds per run is drawn on purpose (notes/test-harnesses.md), not by more seeds.

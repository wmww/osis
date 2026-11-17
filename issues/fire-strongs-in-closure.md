# Fire strongs are closure edges in code, not in spec
> Summary: spec/data-model.md §8 says a reference in a fire adds nothing to a closure, but the engine's closure reads every strong row of the reference index (`units::strongs_from`, `strong_to`), and a durable signal's rows are its held valid fires' references: a strong in a held fire holds its target. Decide which is right and make the other match.
> Priority: low
> Tags: engine, data-model

- `refs::note` indexes a held valid fire's references in the same `node/refs from`/`to` rows as a state's; `units::strongs_from` filters by kind only, not by signal. `retention::needed` counts them too (spec/commits.md §5 What a held thing needs does say "held fires included").
- Either drop signal rows from the closure's edges (a filter in `strongs_from`, `strong_to` and the ticket rejudge, plus a test), or state in the spec that a held fire's strong holds its target while the fire is held (a fire is history from its own `ts`, so this is spec/data-model.md §8 Held history without the flag). The second fits "one mechanism" better but makes every fire's strong pin its target for the fire's keep bound, whatever the setting's flag.

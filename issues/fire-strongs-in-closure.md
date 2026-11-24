# A strong in a held fire holds its target whatever the setting
> Summary: Decided (Tess; notes/stubs.md rule 4): a fire is held history and follows the one rule for references in history, under the thing's setting (`history_holds_targets`). Neither side matches: spec/data-model.md §8 still says a reference in a fire adds nothing to a closure, and the engine's closure holds every held valid fire's strong targets whatever the flag.
> Priority: low
> Tags: engine, data-model, spec

- Spec: drop the signal exclusion from spec/data-model.md §8 (What counts, Held history), so a held fire's strong counts as any held body's under `history_holds_targets`.
- Engine: `refs::note` indexes a held valid fire's references in the same `node/refs from`/`to` rows as a state's, and `units::strongs_from`/`strong_to` read them whatever the flag; they should count only where the setting has the flag, as `refs::kept` does for other history. A test: a strong in a held fire holds its target with the flag and not without.

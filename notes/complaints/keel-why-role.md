# keel-why-role
> Summary: mishaps building why_role, the end-check switch and the new trace lines.

- `tools/mutate.py` with several triples needs each OLD to be an expression; a match arm (`Some(true) => (..)`) fails the one build for all rows, reported only as "does not build" per row: probe arm-shaped edits alone or pick the arm's value.
- A planted fault that breaks setup (`World::redeem` "0 redeems 1's card", the node-closure debug check) hides the clause it was meant to reach: most of a first round of plants failed in fixtures, not where their diagnostic would explain them.
- `Engine::rotated_already` is a transaction that always rolls back (`Misuse("rotated_already rolls back")`), so the `tx rolled back` trace lines carry it on every start: filter it out with grep when reading refusals.

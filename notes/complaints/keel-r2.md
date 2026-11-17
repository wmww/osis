# keel-r2
> Summary: Mishaps while extending the R2 reference index property.

- `Engine::body_page` gives each body's value from its last piece only, and `Fragment::read` of a body alone hides its writes into another's elements: an oracle over held bodies reads `body_fragment` and names values by `each_value` (as written) or `read` (as read), never `HeldBody::value`.
- A mutation of only `m.set(t, &ct::PURGE, &now)` plus a purge item fails with `Build("no aspects")` when `now` equals the last purge time (the set writes no delta): advance the clock first.
- A fire in the commit that also writes the setting keeping its history is refused (`Misuse`: the setting is not yet held); write the setting first.
- `tools/mutate.py` against `-p osis-engine --test it` cannot see a crdt law that only osis-crdt's own property checks: run the crdt plants a second time with `-p osis-crdt --lib`.

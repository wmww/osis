# A purge leaves a map key a delta repeated under a dot no delta owns
> Summary: A delta may hold a map entry record repeating a key under any dot (a write into another's entry). Purging that delta strips its values, but the key stays: it is erased only when the dot's creation is held value-less. A hostile writer (native, or an import) can put a key under a dot no delta owns, kept present by a non-value write (a `W`), so it reads back after the purge.
> Tags: security, crdt, engine

Shape: entry record `(X, "secret")`, X a dot no commit on the thing owns, holding a struct with only the writer's `W` (or a reset). After a purge of the writer's delta, the `W` stays (no value) and the map reads `"secret": {}`.

Imports refuse writes outside their origins since import-dots (spec/permissions.md §7), but key copies under unlisted dots are allowed there (honest split imports repeat each other's keys), as in writer deltas. A fix must keep an honest write into another's entry, whose key belongs to the creator, readable after that write's purge. Options: erase a key copy of a purged delta whose dot no held delta owns (order: an owner arriving later must give its key back); or a dot with no creation anywhere hides its key copies (breaks resurrection of a tombstoned entry, spec/crdt.md §5.6).

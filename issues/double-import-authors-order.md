# Two imports of one origin on a thing make `Core::authors` order-dependent
> Summary: A hostile writer on a copy can hold two imports listing the same origin `o` at different `ts`; `note_authors` keeps the last arrived claim for `(copy, o)`, so carried groups' judging point and `owns_source`'s import lookup (at that `ts` in `copies`) depend on arrival order.
> Tags: security, node, validity

Only a writer breaking spec/permissions.md §7 ("a move is one import by one node") gets here: `move_thing` writes one import per origin into a fresh copy, and receivers do not refuse a second import of `o` on the same thing. With imports I1 (`ts1`, aspect a) and I2 (`ts2`, aspect b) both listing `o`, `Core::authors[(copy, o)]` is whichever arrived last; `validity::owns_source` on aspect a finds I1 only when it holds `ts1`, so a snapshot's `Commit(o)` writes on a are owned by I1 on one node and judged as carried on another.

Fix options: refuse a second import of an origin on one thing (bad input, but then acceptance is order-dependent too unless both are refused), or make the claim a function of the held set (e.g. smallest `(ts, author)` among held imports of `o`, re-derived when one is forgotten) and index imports by `(thing, origin)` so `owns_source` needs no `ts`.

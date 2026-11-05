# held-model-2 (adapter)
- A held-model mismatch in `arrival_order_purge_large` shrinks for 10+ minutes at plain size; `OSIS_ORDER_SHRINK=0` for a quick count of classes, then a shrunk run for one.
- Model keys `(ts, author, commit)` compare author ids: the adapter's ids must follow tid order or keys order differently from the engine. It failed as a validity mismatch that looked like a role-rule difference.
- The brief named "the reviewer's 4 mutants"; notes/testing.md lists five (two caught, three missed); ran four (purge without right, no grace, right at the delta's ts, expired arrival kept a tick).

# A timed edge on a destroyed holder stays a holder for keys for good
> Summary: Holders for keys read no clock, so an edge on destroyed thing t past its `until` but not finalized at the destruction makes its holder a frozen holder of everything t held a role on, boxed at every later epoch until t's own grant there is removed; the destruction is a fixed point, so `until` could be judged against it with no clock.
> Priority: normal
> Tags: security, crypto, engine

**Rule today** (spec/crypto.md §4 Holder actors, Destroyed): t's holders for keys as they stood at its destruction stand in for t; "an edge on t past its `until` but not finalized at the destruction stays a holder ... nobody writes t to finalize it". Code: `Core::key_holders` / `flows::expand_destroyed`.

**Problem**: a timed share on t (a week's read through a group) becomes permanent read on every new epoch of what t held a role on, once t is destroyed before anyone finalized it. Deleting has no safe side (notes/principles.md): keeping that holder is not the cautious choice, it extends a grant past what its writer said.

**Option**: count an edge of t whose `until` is at or before t's destruction point (a record's `expires` `wall_ms`, or the destroying request's `ts`) as ended there. Every node reads the same fixed point, so no clock is read and nodes agree; edges still live at the destruction stand as today. Spec Destroyed and `expand_destroyed` change; Depth0 `D0_destroyed*` gain the case. Untested today beyond `expand_destroyed`'s unit test: add an engine test (t with a passed timed edge, destroy t, rotate A, the expired party unboxed).

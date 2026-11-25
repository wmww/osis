# Destroying a holder ends access through it
> Summary: Build (Tess): a destroyed thing holds nothing and nobody stands in for it, so access through it ends at the next rotation of what it held a role on, as at a removal. Deletes the frozen-holder rule (spec/crypto.md §4 Destroyed, `expand_destroyed`), which also ends the timed-edge leak below.
> Priority: normal
> Tags: security, crypto, engine

**Decided (Tess):** destroying G ends access through G; spec/requirements.md (Purging or expiring a thing's creation): its other holders keep what it held roles on, access through it ends as at a removal. The frozen-holder rule goes whole (spec, `Core::key_holders`/`expand_destroyed`, key access through destroyed things, Depth0 `D0_destroyed*`, notes/holder-actors.md Destroyed holder actors), with the timed-edge case it caused.

## Before (to delete)
**Rule today** (spec/crypto.md §4 Holder actors, Destroyed): t's holders for keys as they stood at its destruction stand in for t; "an edge on t past its `until` but not finalized at the destruction stays a holder ... nobody writes t to finalize it". Code: `Core::key_holders` / `flows::expand_destroyed`.

**Problem**: a timed share on t (a week's read through a group) becomes permanent read on every new epoch of what t held a role on, once t is destroyed before anyone finalized it. Deleting has no safe side (notes/principles.md): keeping that holder is not the cautious choice, it extends a grant past what its writer said.

**Option**: count an edge of t whose `until` is at or before t's destruction point (a record's `expires` `wall_ms`, or the destroying request's `ts`) as ended there. Every node reads the same fixed point, so no clock is read and nodes agree; edges still live at the destruction stand as today. Spec Destroyed and `expand_destroyed` change; Depth0 `D0_destroyed*` gain the case. Untested today beyond `expand_destroyed`'s unit test: add an engine test (t with a passed timed edge, destroy t, rotate A, the expired party unboxed).

**Status (spar-fix-rotation)**: not changed. notes/holder-actors.md (Destroyed holder actors) records Tess choosing the stated limit and rejecting this option ("a smaller leak, still one"). Built and tested, then dropped for her call (about 40 lines): the edges on destroyed things with `until` at or before the destruction's `wall_ms`, filtered in `Core::edge_holders` and added to `members::role_for_keys`'s skip set; a test with peer 1's read ending at +30 s, T expiring at +50 s: X's rotation boxes G, not peer 1 (fails without the filter).
- A closing option with the one existing mechanism: let honest nodes finalize past-`until` edges on a destroyed thing as on a live one. spec/commits.md §5 already holds and judges edge writes on a destroyed thing whatever their stamp; only the writer's refusal to write a destroyed thing stops the finalize. Needs a writer of t still holding it (t is kept while a dependent needs it).

# Moving a text that was reset and then compacted loses content in the copy
> Summary: When a thing is moved to another group, a text or list in it that was once reset and later compacted comes across incomplete: the edits whose original commits were dropped are missing from the copy, because the only carrier left (the snapshot) holds anchor-only elements that the import format forbids. Fix is a small spec choice: allow those anchors in imports taken from a snapshot (recommended) or re-anchor the imported edits.
> Tags: crdt, permissions, node

## The decision (user terms)
- **Allow anchor-only elements in an import that comes from a snapshot** (recommended): the moved copy is complete; the rule-7 exception is bounded like any import.
- **Re-anchor imported edits at the nearest surviving element**: complete too, but the copy's text order can differ slightly from the original where edits hung off erased text.
- **Accept**: moves of reset-and-compacted texts stay lossy; the original is untouched.

## Technical details

spec/permissions.md §7 imports a snapshot's carried writes; spec/crdt.md §3.3 rule 7 rejects a bare-anchor run (no creation, content, position or flag write) in any delta but a snapshot, imports included. A snapshot keeps bare anchors for elements whose writes a reset pruned, so later inserts anchored at them still place. Dropping them from the import leaves those inserts with unknown anchors (hidden, §6.1); keeping them makes every receiver reject the import as bad input.

The node (`moves::carriers`) does not use such a snapshot as an origin. Options: allow bare-anchor runs in import deltas whose origin is a snapshot (a rule 7 edit, bounded by `MAX_DELTA_BARE` like any import), or re-anchor imported elements at the nearest carried ancestor (changes placement).

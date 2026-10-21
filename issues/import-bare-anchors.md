# A move cannot import a sequence's history from a snapshot holding bare anchors
> Summary: Moving a thing whose text or list was compacted after a reset (the snapshot keeps bare anchors) imports that aspect from its remaining ordinary commits only: content whose bodies were dropped is missing from the copy.
> Tags: crdt, permissions, node

spec/permissions.md §7 imports a snapshot's carried writes; spec/crdt.md §3.3 rule 7 rejects a bare-anchor run (no creation, content, position or flag write) in any delta but a snapshot, imports included. A snapshot keeps bare anchors for elements whose writes a reset pruned, so later inserts anchored at them still place. Dropping them from the import leaves those inserts with unknown anchors (hidden, §6.1); keeping them makes every receiver reject the import as bad input.

The node (`moves::carriers`) does not use such a snapshot as an origin. Options: allow bare-anchor runs in import deltas whose origin is a snapshot (a rule 7 edit, bounded by `MAX_DELTA_BARE` like any import), or re-anchor imported elements at the nearest carried ancestor (changes placement).

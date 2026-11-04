# A list element in a snapshot written before its expiry can outlive it at a late node
> Summary: A list element ends at T by a reset the node sets itself (spec/crdt.md §5.7 Live). A snapshot written before T cannot carry that reset, or a holder of the valued delta would lose the element early. So a node holding that snapshot and not the expired commit, which it can no longer fetch, shows others' writes in the element until a snapshot written after T arrives. Honest flow, needs a nested edit and a late node. Maps do not have this (the key-erased record).
> Tags: crdt, engine

Repro: osis-node `waits::list_element_in_snapshot_before_expiry_goes_repro_spec_crdt_5_7` (ignored).

The same node also shows those writes before T, as a partial receipt (spec/crdt.md §4.7). Before the reset rule `Fragment::valueless_of` hid this case for a nested text or struct, though not for an overwritten `list<string>` element, the common hole that rule closed.

Simplest full fix: make it the map's rule. A value-less mark on the creation, a copy of one write where the valued copy wins (spec/crdt.md §4.1). A snapshot carries it before and after T as a `FlagW true` at the creation's own stamp; a holder of the valued delta reads the element until T. Costs a state bit in `SeqElem` and its model twin, and a reader telling the mark from a reset; a real reset above the creation replaces the mark on the wire (the element is not live either way). Laws follow from the copy order.

Cheaper partial fix: a writer holding a snapshot of the aspect from before T writes a new one at T. Needs a writer online, and a timer.

Review's read: narrow, not urgent. It takes a list element (maps are fine), another writer's edit of it, a snapshot between the edit and T, no snapshot or sweep after T, and a node joining after T. Any compaction after T ends it for everyone. The full fix is also a simplification (`strip` and `expire` become one, no `at_node`), so it fits a branch of its own: touches `SeqElem`, the model, wire decode of the mark, copies and deaths.

# A list element in a snapshot written before its expiry can outlive it at a late node
> Summary: A list element ends at T by a reset the node sets itself (spec/crdt.md §5.7 Live). A snapshot written before T cannot carry that reset, or a holder of the valued delta would lose the element early. So a node holding that snapshot and not the expired commit, which it can no longer fetch, shows others' writes in the element until a snapshot written after T arrives. Honest flow, needs a nested edit and a late node. Maps do not have this (the key-erased record). Full fix (the map's rule, a value-less state bit) not built; a mark tried on parked branch `crdt-leftovers` had an un-merge gap.
> Priority: normal
> Tags: crdt, engine

Repro: osis-node `waits::list_element_in_snapshot_before_expiry_goes_repro_spec_crdt_5_7` (ignored).

The same node also shows those writes before T, as a partial receipt (spec/crdt.md §4.7).

Simplest full fix: make it the map's rule. A value-less mark on the creation, a copy of one write where the valued copy wins (spec/crdt.md §4.1). A snapshot carries it before and after T as a `FlagW true` at the creation's own stamp; a holder of the valued delta reads the element until T. Costs a state bit in `SeqElem` and its model twin, and a reader telling the mark from a reset; a real reset above the creation replaces the mark on the wire (the element is not live either way). Laws follow from the copy order.

Cheaper partial fix: a writer holding a snapshot of the aspect from before T writes a new one at T. Needs a writer online, and a timer.

Narrow, not urgent. It takes a list element (maps are fine), another writer's edit of it, a snapshot between the edit and T, no snapshot or sweep after T, and a node joining after T. Any compaction after T ends it for everyone. The full fix is also a simplification (`strip` and `expire` become one, no `at_node`), so it fits a branch of its own: touches `SeqElem`, the model, wire decode of the mark, copies and deaths.

## The mark, tried on a branch
Branch `crdt-leftovers` on origin (parked, not merged; commit 8ca8275f) builds the full fix as a value-less mark on a list creation, with the rule "a copy of a creation without a mark beats it" (no mark means valued). Its gap: an un-merge breaks that rule. `seq::remove_dots` takes the flag of a fallen writer, leaving a value-less creation with no mark, which then beats a valid copy's mark by arrival order, and a reset that replaced a mark takes the mark with it when it falls: order-dependent state, a nested write read shown or hidden accordingly. Repro on the branch: `OSIS_ORDER_SEED=7520033 OSIS_ORDER_LEN=40 cargo test -p osis-node --test it -- --ignored --exact order::arrival_order_list_expiry_large_spec_crdt_4_7` (also 7520028); main has no marks and passes (that oracle is on main).

Tried: `remove_dots` leaving the mark when a flag falls or its creator is removed, implementation and model. Those seeds pass, but `seq_unmerge_spec_4_6`, `seq_remove_writes_rejoins_spec_4_8`, `seq_copies_agree_and_rejoin_spec_perm_5_2` and `hostile_list_matches_model_spec_6_2` fail: stripping then rejoining no longer gives the state (likely cause, not traced: a stripped copy reads ended where no valued copy rejoins).

Simplest rule left: value-less as its own state bit in `SeqElem`, joined with valued winning, carried on the wire beside any reset, so no reset or un-merge can lose it. The branch's other commits are of no further use (removed text keys: spec/crdt.md §5.6 Bare anchors covers it); its `tests_life.rs` cases may be worth taking along. When this issue is fixed or dropped: `git push origin --delete crdt-leftovers` and delete any local branch.

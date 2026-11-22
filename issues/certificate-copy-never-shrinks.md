# A certificate copy outlives the parts it was sealed for
> Summary: an own certificate copy under S carrying parts S's certificates no longer name stays S's log of the commit (it still holds every named part), so what S stores depends on what it once named (spec/commits.md §5: a function of what is held). Constructed case: osis-sync `growth::repro_a_redeemed_and_ended_link_returns_storage_to_a_fresh_worlds_spec_sync_set_3` (ignored): the grantee's account root's sync ID, while it holds K, names the sharer's account `keys.0` and its account root's `keys.0` of the sharer's account creation commit, then the first alone; the copy of both stays, one blob more than a fresh world.
> Priority: low
> Tags: sync

Stage A2 (notes/redesign-plan.md): evidence re-derived from holdings at every change replaces certificate copies and closes this; take it there, not before.

- spec/sync-judgement.md §2 counts a copy outside the required set only when it holds none of the named deltas; a copy holding extra ones is never rewritten.
- Reachable by any piece whose part set shrinks (a read thing's `Piece::Holder` or `Piece::Chain` as a chain loses an edge write). Wanted: rewrite such a copy as a strip is rewritten, or say why the residue is bounded.
- Tried and dropped: counting a copy outside when it holds any delta S does not name (`unnamed_copy` by subset, not disjointness). It broke osis-sync `holding::a_mint_admins_readers_read_a_thing_no_more_once_its_record_edge_goes_*` (the reader kept reading) and `holding::an_ended_way_found_keyless_drops_its_copy_*` (a delivery storm: log, leave, log again), and a copy relogged after the shrink cannot reuse the shared blob (tombstoned under S when it lost to the grown copy), so storage still differs by one blob.
- Once fixed, fold the redeem round into the grant arm (`grants_as_fresh(true, true, 4)`). The redeem arm's `flat_work` (checked after storage) then shows whether its last three rounds' read work exceeds rounds 2-4's (seen once: a one-round spike); make the check or the work flat, never skip it for the arm.

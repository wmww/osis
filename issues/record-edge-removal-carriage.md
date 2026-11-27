# A record edge's removal never reaches the mint admin's readers who took the thing under its unit
> Summary: Bob's node mints T2 in T0's unit, makes it independent and removes T0's record edge before syncing. T2's record, value and grants reached T0's readers under T0's sync ID; the removal goes only under T2's own, which nobody keeps once they apply it. Own siblings, a peer told S2 before it shared it, and any later reader of T0 keep reading T2 through the record edge.
> Priority: normal
> Tags: security, sync

Shown by `holding::a_mint_admins_readers_read_a_thing_no_more_once_its_record_edge_goes_spec_sync_set_2` (osis-sync, ignored). At the end nodes 0 (Alice, reads T0) and 1 (Bob's sibling) hold T0's record edge on T2 and read T2.

Cause: T2's parts went under S0 while T0's unit held T2 (the minting commit also writes T0's `holds`, so it stays under S0 whole). The removal takes T2 out of T0's unit, so by the writer's view it has a body under S2 alone. A T0 reader whose view still holds T2 learns the removal only by syncing S2 and finding a holder of it. The writer keeps S2 only while a peer is to be waited for (spec/sync-set.md §3): its own siblings are skipped (they leave by the same commit), and Alice's node, told S2's credentials before it learned T2 was independent, acked without sharing S2, so the wait ended before either took it. After every holder applies the removal, nobody keeps S2 at all, so a reader of T0 joining later gets the minting commit from S0 with no keyset commit (T2 counts dependent) and reads T2 by the virtual record edge.

The own-removal-with-no-source part (the writer stopped S2 at once and shredded the removal) is fixed: leave keeps a sync ID while an own self-removal with a body under it waits.

Options (a spec/model question: where the edge's removal travels):
1. A removal that takes X out of T's unit also has a body under T's sync ID (the writer's view before the write), leaving S0 with X's other parts once readers agree. T0's readers then learn it from S0, where they took the stale state.
2. X's role entries travel with X's record: wherever a sync ID carries X's record, it carries X's stub (role entries cut to its readers), whether or not T's keys open X now.
3. Waiting alone (count told peers and siblings): not enough, since a reader of T0 arriving after everyone dropped S2 still reads T2.

For the dependent/independent pass (notes/priorities.md; Tess: later). Leaning option 2: it is the stub rule (a unit carrying X's record carries X's stub, which its readers follow), so no carriage of its own.

# A part forgotten with lost access is read again
> Summary: A node that loses access to T2 (T0's record edge on T2 removed, T2 minted under T0) forgets T2's parts, then reads them again for good when a blob of T2's minting is entered under T0's sync ID after the loss (pulled, or its own log made late); entered before the loss, it stays forgotten. Order dependence: `holding::a_removed_record_edge_reaches_a_reader_entering_with_it_spec_permissions_3` fails on main and with the first-sync rule.
> Priority: normal
> Tags: security, engine, sync

spec/permissions.md §3 (Lost access: a node drops every local unit it can no longer read). Whether a reader of T0 still reads T2 after the removal depends on when an entry of T2's minting reaches T0's sync ID in its own store, not on the roles.

## Seen
- `holding::a_removed_record_edge_reaches_a_reader_entering_with_it_spec_permissions_3` (known failure): node 2 makes T0 and T2 under it, grants Alice sync on T2 and removes T0's record edge on T2, all before node 1 has synced; node 1 loses T2 (lost access traced, secrets dropped) and still reads T2's value a pass later. Fails on main (607e4a118, its binary from `tools/bin-at`) as on the first-sync branch.
- On main, the same with T0 made by node 1 and Alice granted read on T0 before T2 is made: node 1 (T0's maker) still reads T2. With the first-sync rule (another's body logged under S only past S's first sync or a pass) it passes; without the rule's made-here clause `holding::a_removed_record_edge_reaches_its_mint_admins_readers_spec_permissions_4` fails the same way.
- Traced (the `_4` test with the made-here clause off): node 1 lost access at one step; a pass later it logged the held blob of T2's minting (`Ceb4786`, held under another sync ID) under T0's sync ID. After that its engine holds a `ou/` row opening that commit's header under T0's epoch, the commit row carries T2's parts again, and T2's aspect row is back. With the log before the loss, none of it.

## Cause, as far as found
`retention::forget` with `Scope::Lost` unreceives the lost parts (they count missing) and keeps the commit's blobs ("an own entry naming one waits for the access to return"). A later entry of a blob of that commit under a sync ID the node still reads (T0's: a minting copy is readable by the admin's readers) opens it and takes the missing parts as received, with no check that they were forgotten for lost access. The fix belongs where a part is taken: a part of a thing this node holds no role on stays forgotten whatever blob brings it (or the forgetting is a standing rule, not an event), so arrival order cannot matter.

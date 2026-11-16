# A node paired after a device removal lacks a contact's thing's newest sync secret
> Summary: In `flows::a_node_pairs_another_after_removing_its_pairer_spec_sync_inbox_1` the node paired after the removal holds the contact's thing (its card's link K, held through D) at the rotation's epoch with a read secret from D's ticket but no sync secret and no `sync.0`, so it syncs the thing's sync ID by the tickets' hint and never opens the entries its siblings must hold there. Before tickets kept their sync IDs through a context move (spec/sync-inbox.md §5) the same node did not sync that thing at all, which the quiet check could not see.
> Priority: normal

The flows test passes again since a node writes only what it holds (spec/sync-set.md §2 Writing; `publish_reach` lists a paired node only once it holds the profile), so its KNOWN line went; the state below was not checked again and may still arise elsewhere.
> Tags: sync, engine, tests

Seen at the end of the test: node 3 (paired by node 2 after node 2 removed node 1) holds the contact link thing in the closure as read, its epochs the rotation's (n 2) with read secrets of n 1 and 2 (not established) and the sync epoch 2 known by its rotation commit with no secret; nodes 0 and 2 hold every epoch, established, and the `sync.0`. So node 3 reads S by hint, pulls its entries, opens none of the bodies (`World::unreached_must_holds`: holders 0 and 2, reader 3).

To settle: where a freshly paired node gets a held thing's sync secret and `sync.0` when D's ticket gives the read secret alone (spec/sync-set.md §1 The account's tickets; notes/inbox.md The account's tickets), and whether D's ticket should box the sync secret too. Likely the custody or pairing owner's.

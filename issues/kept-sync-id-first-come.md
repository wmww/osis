# A sync ID kept for one thing is never kept for its owner
> Summary: An accept keeps no sync ID the account's sync record keeps for another thing (spec/sync.md §3), so whichever thing was accepted first holds it: a forger's own thing accepted under a genuine thing's sync ID keeps the genuine thing from ever keeping it.
> Priority: normal
> Tags: engine, security

- Repro: engine `facade::repro_a_forgers_earlier_accept_takes_no_sync_id_from_a_later_thing_spec_sync_3` (ignored). The forger needs the genuine thing's sync ID (an insider of it, or anyone it was shown to) and the user's accept of the forger's invitation first.
- Effect: the genuine thing, kept unread, syncs nothing under its own sync ID; the user's later accept of it does not help. The rule differs by accept order (notes/coordination.md, Spot incidental dependence).
- Direction: decide ownership by what verifies, not by what came first: a kept sync ID belongs to the thing whose sync secret a step on its path bears (spec/sync-ids.md §4 Owner, as recorded secrets are already judged), so an accept keeps every offered sync ID for its thing (the record only adds) and a sync ID is synced for the thing a verified step ties it to, never by accept order.

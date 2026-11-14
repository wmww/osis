# A link's first contact: what is left after the join
> Summary: a redeemer joins K from the link alone (K's sync ID carries the author chain as certificate copies and the records as a record blob; links::a_redeemer_joins_k_spec_permissions_7), but the redeemed thing is filed nowhere so nothing syncs it after the join and a link whose sharer never answers stays followed.
> Priority: normal
> Tags: sync, tests

- **Filing after the join.** Once the join is held the link is unfollowed (spec/sync-set.md §2), and nothing files K's thing in the redeemer's synced group, so K is synced no more: osis `redeeming_a_link_joins_its_thing_spec_sync_inbox_6` (ignored) reads no content after `redeem`. Contact cards (`import_contact`) file nothing by design (spec/sync-set.md §4); whether `redeem` of a non-profile link files the thing (an accept, spec/sync-set.md §4) is the osis API's to decide.
- **The redeemer's other end** (spec/permissions.md §7): every route of K's sync ID failed to open it, one at least refusing L's static entry. Only the role-history end is built (`Engine::link_ended`), so a link whose sharer node never answers stays followed (one per redeem the user asked for, durable in `I/r/`) until K's history arrives.
- A link lists relays only (spec/wire.md §10), so a sharer with no relay is reached by a link only over a LAN.
- Record blobs pulled from a peer are taken (their records learned) but not kept: each reader logs its own record blob of the records its own store lacks (`read`'s `records`), so one record blob per node per sync ID.

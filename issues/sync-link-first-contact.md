# A link's first contact: a sharer that never answers
> Summary: a redeemer joins K from the link alone (K's sync ID carries the author chain as certificate copies and the records as a record blob; links::a_redeemer_joins_k_spec_permissions_7) and the join files the target (spec/sync-set.md §4), but a link whose sharer never answers stays followed.
> Priority: normal
> Tags: sync, tests, tess-call

- **The redeemer's other end** (spec/permissions.md §7): every route of K's sync ID failed to open it, one at least refusing L's static entry. Only the role-history end is built (`Engine::link_ended`).
- **A sharer that never answers**: the spec ends a link by a refusal or by held role history, and a silent sharer gives neither (the link text carries no `until`, and L's grant with its `until` comes only with K's history), so the link stays followed (one per redeem the user asked for, durable in `I/r/`, its sharer key dialed at the redial pace) until K's history arrives. No picked timeout: at 0 a sharer offline for a moment ends the link, at infinity it is today's behavior. Proposal (needs Tess): (a) the link text carries L's grant's `until` (spec/wire.md §10, optional like `flags`), and the redeemer stops at it with nothing held; (b) a link with no `until` is followed until the user withdraws it: an osis call ending a redeem (forget the seed, unfollow, drop the `I/r/` row), since dropping the `redeem` future deliberately keeps redeeming across restarts.
- A link lists relays only (spec/wire.md §10), so a sharer with no relay is reached by a link only over a LAN.
- Record blobs pulled from a peer are taken (their records learned) but not kept: each reader logs its own record blob of the records its own store lacks (`read`'s `records`), so one record blob per node per sync ID.

# A link's first contact: the refusal end
> Summary: a redeemer joins K from the link alone (K's sync ID carries the author chain as certificate copies and the records as a record blob; links::a_redeemer_joins_k_spec_permissions_7) and the join files the target (spec/sync-set.md §4), but the redeemer's refusal end is unbuilt.
> Priority: normal
> Tags: sync, tests

- **The redeemer's other end** (spec/permissions.md §7): every route of K's sync ID failed to open it, one at least refusing L's static entry. Only the role-history end is built (`Engine::link_ended`), and only before the join: a joined link revoked before any source took its join (finalized, or its single use taken by another redeemer) whose sources all refuse L, so the revocation never arrives, is followed until this end exists (its row, L and the sharer dialed at the redial pace).
- A link lists relays only (spec/wire.md §10), so a sharer with no relay is reached by a link only over a LAN.
- Record blobs pulled from a peer are taken (their records learned) but not kept: each reader logs its own record blob of the records its own store lacks (`read`'s `records`), so one record blob per node per sync ID.

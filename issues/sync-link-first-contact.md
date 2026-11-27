# Link redeemer: the refusal end, and first contact without a relay
> Summary: A redeemer joins K from the link alone (K's sync ID carries K's evidence as certificate copies and the records as a record blob), but its refusal end (spec/permissions.md §7: every route of K's sync ID failed, one refusing L's claim) is unbuilt, so a revoked link whose sources all refuse L is followed for good.
> Priority: normal
> Tags: sync, tests

- Only the role-history end is built (`Engine::link_ended`), and only before the join: a joined link revoked before any source took its join (finalized, or its single use taken by another redeemer) whose sources all refuse L's claim, so the revocation never arrives, is followed until this end exists (its row, L and the sharer dialed at the redial pace).
- A link lists the sharer's relays, not its socket addresses, plus its configured addresses (spec/wire.md §10), so a sharer with no relay and no configured node is reached by a link only over a LAN.

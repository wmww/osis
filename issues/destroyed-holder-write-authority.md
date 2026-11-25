# Writes through a destroyed holder after its destruction
> Summary: With access through a destroyed thing G ended (spar-destroyed-ends), authority through G still counts for writes stamped after G's destruction, so a party holding A only through G may still write A validly under an old epoch (honest nodes stop: no current epoch). As at a removal, writes stamped after the destruction point would be invalid; notes/expiry-creation-design.md rejected cutting authority at destruction for reasons that predate the decision.
> Priority: normal
> Tags: tess-call, perm, engine

Tess decided destroying G ends access through it, "as at a removal". At a removal, writes stamped after it fall. Through a destroyed G today they stand (validity reads G's edge writes whatever the destruction). Options:
- **Cut at the destruction point**: a write through G stamped after G's destruction (an expiry's `wall_ms`, a purge request's `ts`) is invalid, as one after a removal; past writes stand as their edge writes say. The rejection in notes/expiry-creation-design.md ("everything reached through it would lose its readers and admins at once") is now the decided behaviour for keys; what remains to check is a purge request that later falls (the cut must go with it, as at a removal that falls) and backdating (a purge's `ts` is its signer's).
- **Keep as is**: an accepted gap like a keyless grant's write authority.
Recommendation: cut at the destruction point, by the removal's rule, if the falling-purge case composes; else keep and state it.

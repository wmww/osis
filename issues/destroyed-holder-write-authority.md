# Writes through a destroyed holder after its destruction
> Summary: Access through a destroyed thing G ends, but authority through G still counts for writes stamped after G's destruction, so a party holding A only through G may still write A validly under an old epoch (honest nodes stop: no current epoch). As at a removal, writes stamped after the destruction point could be invalid; notes/expiry-creation-design.md rejects cutting authority at destruction only so past writes keep their history, which such a cut keeps.
> Priority: normal
> Tags: tess-call, perm, engine

Tess decided destroying G ends access through it, "as at a removal". At a removal, writes stamped after it fall. Through a destroyed G they stand (validity reads G's edge writes whatever the destruction). Options:
- **Cut at the destruction point**: a write through G stamped after G's destruction (an expiry's `wall_ms`, a purge request's `ts`) is invalid, as one after a removal; past writes stand as their edge writes say. Keys already end there (notes/holder-actors.md, Destroyed holder actors); to check: a purge request that later falls (the cut must go with it, as at a removal that falls) and backdating (a purge's `ts` is its signer's).
- **Keep as is**: an accepted gap like a keyless grant's write authority.
Recommendation: cut at the destruction point, by the removal's rule, if the falling-purge case composes; else keep and state it.

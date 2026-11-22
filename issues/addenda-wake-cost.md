# Addenda's wake climbs a removed party's whole reach
> Summary: `flows/addenda.rs` wakes the removals filed under every party a commit stamped no later than the newest filed removal reaches (`wake`, `Held::reach` from its author, edge targets and everything upstream of its edge holders): a backdated edge write by a removed party with a wide reach costs O(that reach) plus one judgement per filed removal it reaches. perm should report the removals whose demotions moved instead.
> Priority: normal
> Tags: engine, perm, security

`flows/addenda.rs` keeps each removal's gathering (whether it applies, its candidates) and judges it again only on what it reads (notes/engine-roles.md, Addenda). Who R demotes can move by a commit ordered before R that changes no walk change of R's own (a member joining a realm R names, a named holder's other path taken away), so the wake climbs from each such commit to every party it reaches.

Measured (debug probe, a removed party X holding k things, j backdated commits after R): content: 0 removals judged, k+3 parties per commit; edge writes (junk grants to the remover): 1 judgement of R and about k+30 parties per commit (43 at k = 10, 137 at k = 100). perm already re-walks the component from that commit's point, which this does not exceed in kind.

Wanted: perm's `Changed` naming the removals whose demotions (`Timeline::demoted_by`) moved, so the wake reads that instead of climbing. Count test: a removed party with reach k writing j backdated edge writes after R: parties climbed at k and 10k equal.

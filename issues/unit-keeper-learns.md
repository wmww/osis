# What may a node keeping data unread learn about references and grants?
> Summary: To follow a closure it cannot read, a node gets from each unit it keeps an opaque handle per thing the unit references (the same handle wherever that thing is referenced) and one sealed entry per thing the unit's thing was granted sync or above on. spec/requirements.md Data a node cannot read allows "which of them refer to which" among kept units and forbids learning role grants; handles of things not kept and the number of grants go beyond those words. Tess: accept the wording, or pay to hide more.
> Priority: normal
> Tags: tess-call, sync, security, spec

## The question
A storage node keeps your data without reading it and must fetch what your things reference, including things reached through a folder whose writers know nothing of them. For that each unit tells it (notes/sync-unit-design.md §2, §3):
- **A handle for every thing the unit references**, kept or not. The node learns how many there are, which kept units reference a common thing, and, if it ever learns a thing's ID, whether a kept unit references it.
- **One sealed entry per grant the unit's thing holds**. The node opens an entry only when a unit it keeps references that thing, which is when it may fetch it; of the rest it learns how many there are and whether two kept units were granted the same thing.

It learns no ID, no content, no roster, no role, and no network name of a unit it may not fetch (the earlier design showed it the sync ID of every referenced unit).

Is that acceptable, with the requirement's words changed to say so?

## The answers
1. **Accept, as designed.** spec/requirements.md Data a node cannot read: "which of them refer to which" becomes "an opaque handle for each thing they refer to, how many units each kept thing may enter, and which kept unit holds the key to which"; "never ... its role grants" becomes "never whom a grant is to or what role it gives".
2. **Simpler, shows more**: the grant entries unsealed. The node then also learns the network name of every unit your thing was granted, referenced or not (it holds a secret those units accept, so it could fetch their ciphertext). One key derivation less per entry.
3. **Shows less, costs more**: handles made different in each unit. A node keeping a closure unread could then no longer join a reference in one unit with a key in another, which is the case the design exists for (a root that can sync what a folder inside it cannot); it would hold such a thing only where the referring unit itself was granted it. That gives up a node keeping your data unread holding everything your nodes hold.

## Recommendation
Answer 1. A node that stores a closure must know its shape; the handle is the least that lets it follow a reference whose writer knew only an ID, and sealing the grant entries costs almost nothing.

## Meanwhile
The plan (notes/redesign-plan.md, B1) proceeds on answer 1; the requirement's wording is put to Tess with B1's spec brief. Answer 2 is a deletion (the sealing). Answer 3 changes what such a node holds and would reopen the design.

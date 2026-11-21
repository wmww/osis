# A thing's readers can always see its other readers
> Summary: Every holder of a thing opens all its role data, the roster included (spec/crypto.md §4 Roles secrets), so nothing can be shared with a chosen set without each learning who the others are. Tess: this should be possible to do well, as an option a thing's admins choose, not the default. To design after stage A2 (evidence per sync unit, notes/redesign-plan.md).
> Priority: normal
> Tags: perm, crypto, sync, spec

What a reader needs of the roster: the writers' grants (to judge writes) and its own. It changes no keys, so it needs no other reader's grant. Today it also uses the roster to find peers to sync the thing with.

Wanted (Tess): an option on a thing under which reader-level grants open only for holders at write or above: who may write is visible to everyone who reads, who reads only to those who write. Not the default: hiding readers consistently costs them syncing with each other (below), which most things should keep. Uses: an audience of readers (a published thing), contact-only information such as a dial list. A reader of such a thing no longer fetches and checks every other reader's grant.

Costs and points to design:
- **Readers finding each other by syncing.** Answering another node's offer of the thing proves you hold it, so hiding readers strictly means a reader offers and answers only to those it knows are inside (the writers, nodes keeping the thing unread), and readers do not sync it with each other. Tess: if that becomes a sticking point, or costs sync efficiency beyond these things, drop this part: the property is then that readers are not listed to each other, while two readers that connect anyway may learn they share the thing.
- How role data is sealed per level (role parts open today under any epoch's roles secret, spec/crypto.md §4), and what a holder granted read later sees of earlier grants.
- How a reader learns of its own removal, and of a writer's (it holds writers' grants).
- The count of readers shows unless padded (claim sets at nodes keeping the thing unread are padded already).
- With intermediary things as the only tool today (a thing per recipient holding the role), each recipient costs an independent thing: not the answer.

Checked against the path and membership designs (notes/write-path-design.md §2, Readers hidden from each other): no conflict with validity, evidence or the public thing, since every edge a content path names is a writer-level grant, which readers still open. Sealing by the value an edge write sets (at or below read, and ending an entry at or below read: for writers only) keeps every write a reader's walk needs open. Two points for this design:
- An act made at read through a holder shows that reader-level edge to the target's readers as evidence: leave such acts to writers, or accept that their maker shows.
- A removal's copy is in a unit only where it is evidence of a write held there (notes/write-path-design.md §2, D1 to D4), so it names the removed party to no reader of a unit it only reads; where a reader-level act brings a copy, seal it for writers.

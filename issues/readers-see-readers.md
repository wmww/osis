# A thing's readers can always see its other readers
> Summary: Every holder of a thing opens all its role data, the roster included (spec/crypto.md §4 Roles secrets), so nothing can be shared with a chosen set without each learning who the others are. Tess: this should be possible, as an option a thing's admins choose, not the default. To design.
> Priority: normal
> Tags: perm, crypto, sync, spec

A reader needs of the roster only the writers' grants (to judge writes) and its own; it also uses the roster to find peers to sync with.

Wanted (Tess): an option under which reader-level grants open only for holders at write or above: who may write is visible to every reader, who reads only to writers. Not the default: hiding readers costs them syncing with each other. Uses: an audience of readers (a published thing), contact-only information such as a dial list.

To design:
- **Readers finding each other.** Answering an offer of the thing proves you hold it, so strict hiding means a reader syncs it only with writers and nodes keeping it unread. Tess: if that becomes a sticking point, or costs sync efficiency beyond these things, drop it: the property is then that readers are not listed to each other, while two readers that connect anyway may learn they share the thing.
- How role data is sealed per level (role parts open under any epoch's roles secret today), and what a reader granted later sees of earlier grants.
- How a reader learns of its own removal, and of a writer's.
- The count of readers shows unless padded.
- An intermediary thing per recipient is no answer (an independent thing each).

Checked against notes/write-path-design.md §2 (Readers hidden from each other): no conflict with validity, evidence or the public thing, since every grant a content path names is writer-level. Two points: an act made at read through a holder shows that reader-level grant to the target's readers as evidence (leave such acts to writers, or accept that their author shows); where a reader-level act brings a removal's copy into a unit, seal it for writers.

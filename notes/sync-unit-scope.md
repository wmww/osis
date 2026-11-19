# What a sync unit covers
> Summary: Tess's decision that a sync unit becomes one independent thing and its dependents, a closure being synced unit by unit; why, what it is meant to win, how the privacy story is kept as tight as practical, two mitigation ideas not planned, and a record of the readable-closure model that is built and being left, with its trade-offs.

Principle: **a sync unit is one independent thing and its dependents; a closure is a set of units, synced by walking it.** Sharing a root still gives its closure, and promoting a thing to independent still changes nothing an app or user observes. The work: issues/sync-unit-dependent-tree.md.

## Why (Tess)
The built model carries every independent thing of a root's readable closure under the root's sync ID as well as under its own. What that buys is one property: a node keeping a root unread sees one bag of blobs and nothing of its inside. That property holds only while the node keeps none of the inner independent things under their own sync IDs; where it does, the same blobs under both show exactly which thing sits inside which. Things are independent in order to be synced with their own audience, so the property holds when they are not synced there and fails when they are. It does not earn what it costs: an entry and stamp per enclosing unit on every commit, deposits into enclosing units, retag, per-sync-ID copies, and the code and bugs that go with them.

## What the change is meant to win (claim all of it)
- A commit is entered once, under the unit of the thing it writes (a commit touching things of several units still goes as one blob under each).
- No retag: adding or removing a reference to an independent thing is one small write, whatever the thing's size.
- No deposits by a nested thing's writers into an enclosing unit they cannot write, and no promotion of those.
- No per-sync-ID copies made because a unit's readers cannot open every section of a shared blob.
- One rule for walking a closure: at an independent thing, enter its unit by a secret held for it. "This unit's keys open that thing" stops deciding what a sync ID carries.
- A public thing (issues/actors-one-mechanism.md, profiles) is simply a unit anyone may enter, reached by the reference to it.
- Evidence, removals and status are each stated once per unit, with no case for a thing under several.
- Fewer states for the differential and the sim to cover; the sync leftovers that exist only for multi-unit carriage close without being fixed.

## Keeping the privacy story tight
A node keeping units unread must be able to follow a closure, or promotion would take a thing out of what it stores. So each unit lists its direct independent members, readable by holders of sync on it, written in the commit that writes the reference; such a node follows the edges and keeps a unit while a unit it keeps points at it. What it learns that it did not before: how many independent things a closure has, which refers to which, and which are busy. To keep that as small as practical:
- An edge names an opaque sync ID and what is needed to keep it unread, nothing of what the thing is, who holds it, or its role in the referrer.
- Edges open for holders of sync on the referring unit and for nobody else: not for a node that merely relays, and not in the clear.
- Nothing per writer rides across a writer's units beyond what judging needs (issues/sync-units-linked-at-rest.md).
- Blinded delete keys, padding, and no identifier predictable without a read key stay as they are.
- Rejected ways of hiding the edges, and why: a flat list at the root (every inner unit carries its own list, so the tree can be put together anyway); peers telling the node which units to keep while it counts references (it knows the counts and not the edges, readers the edges and not the counts, so neither can release what a dropped unit referenced, and a cycle never reaches zero); the same per root, computed by readers of the root (only they can update it, so a promotion by someone who reads only an inner unit waits for one).

## Mitigations a user could choose (ideas only, Tess; not planned, not known to work)
- **Sync this closure encrypted separately**: a closure carried as one bag again, encrypted for that purpose, for a user who wants a node keeping it unread to see nothing of its inside and accepts the duplicate bytes.
- **Dependent things only in this thing's closure**: no thing inside it may become independent, so it stays one unit; granular sharing and permission changes inside it are given up.

## The readable-closure model, as built and being left
Kept on purpose (Tess, a deliberate exception to notes holding no past states) for when the question comes back. It describes spec/sync-set.md §2 and spec/sync-judgement.md §1-§2 while they stand.
- **What it is**: the sync unit of an independent thing T is T and each thing reached from it by strong references, through things T's keys open only, that T's keys open, dependent or independent (T's keys open X when X's secrets derive from T's or T holds read or above on X's independent). T's sync ID carries exactly that unit. So a thing may be carried under several sync IDs and is stored once per node; an independent thing is carried under its own sync ID too, which a reader follows as well (the sync set holds the sync ID of every independent thing in the node closure).
- **Machinery it needs**: one blob per commit with a wrap and stamp under each sync ID that carries it; retag when a thing joins or leaves a unit (its live blobs added under, or deleted from, that sync ID); deposits and their promotion for what a non-writer of a sync ID must log there; per-sync-ID copies where a unit's readers cannot open every section of the shared blob; certificate copies placed by what each sync ID's thing may read; "every reader of T computes the same unit" as an invariant the sync differential checks.
- **What it bought**: a node keeping one root unread, and none of its inner things separately, sees one bag: no count of independent things, no nesting, no per-thing activity. One sync ID suffices for such a node to hold a whole readable closure, and promotion changes nothing for it, since every sync ID that carried a thing keeps carrying it.
- **What it cost**: about 153 B and a signature per enclosing unit per commit; work in the size of a thing whenever a reference to it changes; the deposit and copy paths, among the least settled code (issues/differential-full-size-classes.md and the sync leftovers); the bag's privacy lost at any node that keeps an inner thing under its own sync ID or two overlapping roots, where the shared blobs show the overlap exactly; bursts of entries when a thing is attached or detached, showing its extent to a node that watches.
- **Why it lost**: the one thing it protected is visible wherever independent things are actually synced on their own, which is what they are for.

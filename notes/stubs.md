# Stubs
> Summary: The design for how a node comes to hold, and keeps, what it needs to sync a thing without its content (Tess; decided, not built): a sync unit carries each thing whole or as a stub; strongs bring things in whole, weaks bring in stubs; references in held history follow one rule, fires included; an inbox is a thing of its own; a grant fire carries the data to make a stub and a weak reference, its only special treatment. With what it replaces in the built tree and the questions left for the spec.

**Principle: a grant is a property of the thing granted, never of its holder (Tess).** A holder may be granted a role and have no way to the thing, or not know of it: nobody can make another track, remember or sync what they granted. A notice of a grant is a notice: it expires, and with it what the holder knew. No list of grants is kept with a holder, and nothing below needs one.

## The rules (decided, Tess)
1. **A stub** of an independent thing is its role part (its roster, the boxes handing its keys to its holders, its sync ID and steps), cut to the boxes the readers of the unit carrying it can open, and none of its content. It is what a node needs to start syncing the thing, and it is kept current: a node holding a stub follows the thing's role entries as they change.
2. **A sync unit carries each of its things whole or as a stub.** A strong to a thing the unit's keys open brings it in whole. A weak to a thing the unit's keys open brings in its stub, where no strong brings it in whole. A reference to a thing the unit's keys do not open brings in nothing. A holder on the chain by which the unit's keys open a thing it carries is in the unit as a stub: nothing is carried for a holder for having been granted something.
3. **A node syncs a thing whole** if any unit it syncs carries it whole, else as a stub if any carries its stub.
4. **References in held history follow one rule, fires included.** Where a thing's setting says its history holds targets, a reference in a held body counts as in a current value: a strong holds its target whole, a weak its stub, while the body is held. A fire is history from the moment it is written, so a signal is no exception.
5. **An inbox is a thing of its own**, strongly referenced by what takes grants there, so its setting (which signals it takes, how long it keeps them, that its history holds targets) governs nothing else.
6. **A grant fire carries the data to make the stub, and a weak reference to the thing granted.** That is all that is special about the grant signal: nothing the receiver syncs carries the stub yet. From there rule 4 holds the stub while the fire is held, rule 1 keeps it current (a key change or a removal after the fire reaches the holder as it would any stub), and a reference of the receiver's own keeps it (a weak) or syncs the thing (a strong) past the fire.

## What follows
- **First entry is by an offer or by a unit already synced carrying the thing.** A reference to a thing nothing the node syncs carries, with no offer held, holds nothing, whatever role the node's account has through holders. Whether a shared space files what it was granted is its app's choice.
- **A second node of an account needs nothing of its own**: the account's unit carries what the account references, whole or as stubs, with the stubs of the holders in between.
- **Unsyncing keeps the way back**: a strong made a weak drops the content and keeps the stub; any node of the unit can make it strong again and sync from wherever the thing is served.
- **Staying current needs a source of the thing's role entries**: a node reaching none misses its key changes until it does.

## Against the built tree
- Held for keys (spec/sync-set.md §2) is the stub of a holder on a chain: the same state, entered there only for holders. A held grant fire keeps what it carried while it is held, as a snapshot nothing corrects.
- The key part under a holder's sync ID (spec/permissions.md §4 Key part) carries an edge piece for every thing the holder holds a role on that a node syncs: rule 2 keeps only those on chains to things the unit carries.
- spec/data-model.md §8 says a reference in a fire adds nothing to a closure and that Held history excludes signals and aspects of fixed retention, giving no reason; the engine counts a held fire's strong as a closure edge whatever the flag (issues/fire-strongs-in-closure.md). Rule 4 replaces both.
- An account's inbox is a thing of its own; any other independent thing is its own inbox (spec/sync-inbox.md §1). Rule 5 makes the first the rule for all.

## For the spec piece
- An external signal enabled on a dependent thing works as on any, or makes it independent unseen: a difference an API caller can observe is a bug (issues/behaviour-depends-on-own-keys.md). Which of the two: a fire sealed to its independent's key and deposited under its independent's sync ID costs almost nothing; an independent inbox about 15 KB, mostly keys. Nothing is known to need independence; not checked against the code.
- How a thing publishes which thing is its inbox.
- A grant fire cut to the stub's data alone: today it carries the role commit's copy with its evidence because the engine holds no secret from a box it has not judged. A stub fetches the target's own role entries, which may judge the box instead; not checked.
- Own boxes only (a node following a stub fetches the boxes it opens, not every holder's): not built, and a commit applies only with all its pages.
- A box is trusted only with the evidence that judges its commit, so a stub in a unit is its boxes plus that evidence.
- Each stub is one more sync ID a node follows (issues/many-sync-ids-cost.md).
- spec/requirements.md, for Tess once built: the stub as a concept beside the sync unit.
- Not modelled: rule 2's cut of the key part, rule 4, a stub from a fire. Model first (notes/principles.md).

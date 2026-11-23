# A commit's signer can delete its own blobs at stores whatever their purge-by
> Summary: No node checks *which* key a header lists at a delete level (spec/sync-hostile.md §2), so a non-admin signer lists its own key at level 1 and deletes its fixed-`admin` parts (a may-grant holder's grant, a `secrets.0` box, `created.0`, `addenda.0`) at nodes keeping S unread, also after demotion. Direction decided, built at A2: delete keys are step keys, the steps a write lists ride with it as evidence, readers check levels 1 and 3 against them; a write is valid only on its writer's side of a fork (F6).
> Priority: normal
> Tags: security, sync

## The hole
Levels already follow purge-by: a header lists exactly the levels a delta's purge-by calls for, and fixed aspects carry their fixed purge-by (`Header::validate`, spec/wire.md §4). The hole is the key's identity: an `admin` part lists one level-1 key, and nobody checks that it is the thing's admin key, so the signer deletes the part at stores with only S's sync key. Linked blobs widen it: a link's delete keys are "its writer's claim, never checked when reading" (spec/data-model.md §6), and pages of role-class deltas are linked blobs, so a check on the header alone leaves pages and chunks open.

Store-side checks do not close it: a store cannot tell which thing a blob serves, so it cannot know whose admin level 1 means (things in S's unit with their own admins have other delete bases), and S's current admins already delete anything with the head's delete key (`DeleteItem::sign`).

## The design (notes/redesign-plan.md A2, Delete keys are step keys)
- A role secret's delete key is its step key: level 1 = `kdf("sync delete", admin)`, level 3 = `kdf("sync write", write)`; `keys.0` keysets drop `delete_key`. Key bases reuse their signing key.
- A writer lists the matching key of the newest step its side holds for the level's delete base. The listed step, with its path back to the base's first step (each step verifies under its prev's delete key, spec/sync-ids.md §6), rides with the write as evidence (A2's one mechanism), so a reader of a thing made independent judges its derived-era content listing the former base's steps without reading that base.
- Readers check each level-1 and level-3 key against those steps, accepted only at points before the commit (no commit supports itself through a step another of its era records). A key not yet placed leaves the part invalid until the step arrives. Every link's and page's delete keys are checked against its delta's (levels 1 and 3 equal; level 2 by spec/sync-ids.md §1's reuse rule); a chunk link that fails reads as absent.
- Level 2 stays unchecked: it is the purge author's right, which the signer holds itself.
- Stores do not change: a commit with a wrong key is invalid everywhere, so deleting it loses nothing.
- In a permanent admin dispute a writer's commits list its side's newest step and are invalid on the other side: intended (Tess, notes/write-path-design.md §1 F6).
- Not modelled yet (notes/holder-access-study.md, the spec brief's).

## Left with it
- Designs that read a party's writes as valid on both sides of a fork, to rewrite under F6: notes/disputes.md, Storage under a fork ("members carry clean bodies across"; "cover only under snapshots valid on both sides"; the oracle "other things read the same on both sides").
- issues/demoted-writer-deletes-at-stores.md: its option 1 (level 2 needs the head's write key) then closes it completely; the step design removes its residue (a writer that listed its own key at level 1).

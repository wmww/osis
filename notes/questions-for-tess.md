# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2. The two below: notes/keys-requirements-study.md.

## 1. Timed shares: who ends them, and when do keys change?
Words used: a **timed share** gives someone access "until" a time. A **writer** is anyone in the group who may write. **Rotating** means making new group keys that only the remaining members get. **Clock drift** is how far a device's clock may be off; we allow a fixed amount.

Example: Alice shares a group with Bob "until Friday". Carol is a writer in the group.

Today, after Friday, each writer's device checks its own clock before writing and rotates the keys if Friday has passed. This is the only place keys depend on clocks, and it costs special cases.

You already agreed: Friday passing should not by itself change keys; an explicit removal should.

Your two points, checked:
- **Leaving on your own is not clock-based.** When Bob leaves by himself, he writes a normal "I left" change. Any writer who sees it rotates before their next write. No clock involved. It stays as it is.
- **Your rule for timed shares works.** When Carol is about to write and her clock says Friday has passed, she first writes "remove Bob" (in the same change). That removal rotates the keys like any removal. Carol needs no admin rights for this, but only for a share that has already ended, and only for shares no higher than her own role (ending a timed admin share still needs an admin). Other devices check it the normal way: the removal's own timestamp must be after Friday. A removal of a share that has not ended does nothing. Someone faking an early time can end Bob's access at most the allowed clock drift early, which a fast clock can do today anyway.

What stays exposed: if Carol's clock is slow, she may write a little after Friday under keys Bob still has (same as today). A device that ignores the rule can do that, but it could also just leak the content. A group where nobody writes after Friday has no new content for Bob to read. Bob's own changes after Friday already do not count.

- **A (recommended):** this rule. Keys stop reading clocks; Bob's leaving on his own stays as today; shared links keep their current ending. It is sound as checked above; its one new piece is the permission for a writer to remove an already-ended share.
- **B (fallback, which you said is fine):** only an admin or the sharer writes the removal and new keys, as links do today. No new permission, but Bob keeps reading new content until an admin's device is online after Friday, while Carol keeps writing under the old keys.
- **C:** keep as is.

## 2. How far should a group's keys look inside its member actors?
Today, when a device leaves a person, every group the person reads must learn of that exact departure (names in history boxes and on grant boxes, bound seals, placed revokes) before any writer uses the group's keys. It is the largest machinery in the system, its review has not happened, and it is what leaks member rosters to every reader (the open privacy issue).
- **A (recommended):** a group seals to a member's current keyset and rotates when that keyset is superseded; it never learns who left the member. Protection against departures inside a member is then only as good as the member's own keyset: if a sibling device rotates the person without knowing of the removal, or the removed device forges the person's keyset while the removal is withheld from the group's writers, the removed device reads the group's new content until the person's next knowing rotation. Today those same rare cases lock the whole person out of the group instead. Direct removals from the group are protected exactly as today. Deletes about 2k lines and three open issues; needs a short model check before building.
- **B:** keep as is (then the redesign's review and the roster-privacy fix stay on the list).
- **C:** keep the machinery, cap the nesting depth: deletes almost nothing, the cost is at depth 1.

## 3. May co-readers of a change see who owns the parts they can't read?
With whole commits (one package per change, branch whole-2b), each locked part carries the list of its thing's owners up to its group or person, unencrypted inside the package, so a device that can open it knows where to find the key. Everyone who receives the package sees those lists, including readers who can't open that part: they learn that the change also touched a thing owned by, say, a private group, and that group's ID. They already see the thing's own ID today, not its owners. Background: issues/section-owner-chain-clear.md.
- **A (recommended for now):** accept it, and say so in spec/requirements.md. It only shows IDs, never content or membership, and only to people who already share a change with that thing.
- **B:** hide it. A reader usually holds the thing's record and can find the owners there; only a first change to a short-lived (ephemeral) thing would still need another way. That means more rules in the hottest code path.
whole-2b merges with A's behaviour; B can follow if you prefer it.

## 4. Should a purge reach an undo made before its device saw the purge?
Undo restores a value (an old register value, a deleted list item) by writing it again as a new change. An undo made after the device holds the purge never restores purged content. But if someone undoes while the purge is still on its way, the restored copy is their own change, and the purge of the original does not touch it, so the content stays. Background: issues/copies-outlive-purge-expiry.md.
- **A (recommended):** accept and say so in spec/requirements.md ("Undo never brings back what another party purged, once the undoing device has seen the purge; an earlier undo is its own change, purged on its own"). Purging the whole history of the field reaches both.
- **B:** every undo marks which original each restored value copies, so a purge reaches the copies too. A wire and engine change across every undo kind for a rare race.

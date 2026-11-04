# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2. The two below: notes/keys-requirements-study.md.

## 3. May co-readers of a change see who owns the parts they can't read?
With whole commits (one package per change, branch whole-2b), each locked part carries the list of its thing's owners up to its group or person, unencrypted inside the package, so a device that can open it knows where to find the key. Everyone who receives the package sees those lists, including readers who can't open that part: they learn that the change also touched a thing owned by, say, a private group, and that group's ID. They already see the thing's own ID today, not its owners. Background: issues/section-owner-chain-clear.md.
- **A (recommended for now):** accept it, and say so in spec/requirements.md. It only shows IDs, never content or membership, and only to people who already share a change with that thing.
- **B:** hide it. A reader usually holds the thing's record and can find the owners there; only a first change to a short-lived (ephemeral) thing would still need another way. That means more rules in the hottest code path.
whole-2b merges with A's behaviour; B can follow if you prefer it.

## 4. Should a purge reach an undo made before its device saw the purge?
Undo restores a value (an old register value, a deleted list item) by writing it again as a new change. An undo made after the device holds the purge never restores purged content. But if someone undoes while the purge is still on its way, the restored copy is their own change, and the purge of the original does not touch it, so the content stays. Background: issues/copies-outlive-purge-expiry.md.
- **A (recommended):** accept and say so in spec/requirements.md ("Undo never brings back what another party purged, once the undoing device has seen the purge; an earlier undo is its own change, purged on its own"). Purging the whole history of the field reaches both.
- **B:** every undo marks which original each restored value copies, so a purge reaches the copies too. A wire and engine change across every undo kind for a rare race.

## Decided (Tess), to build
- Q1: option A, any writer finalizes an ended timed share (role no higher than its own) with an explicit removal that rotates; self-removal stays a departure; admin-only finalize is an accepted fallback if any-writer hits trouble. notes/keys-requirements-study.md §2.5.
- Q2: option A, a group never looks inside its member actors (seals to a member's current keyset, rotates when it is superseded). notes/keys-requirements-study.md. Needs a short model check before building.

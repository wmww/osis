# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2.

## 1. Changes that touch two things: all at once, or per thing?
Today: when one change touches two things (say, moving an item from one group to another), a device shows all of it or none of it. This already has three written exceptions, and it keeps causing bugs (about 10 fix rounds, 8 open issues).
Proposal: all of a change's parts on one thing still appear together, but across things each part appears as soon as its thing arrives. An app could briefly see the item in the new group before it leaves the old one.
Gain: deletes a lot of waiting code and most "which part arrived first" bugs.
Recommendation: yes, unless you rely on cross-thing all-or-nothing for something.

## 3. Cost of removing someone from a group with long history
Requirement: removing a member never costs more as history grows. Removal works correctly; meeting the cost goal needs a second, more complex format.
Proposal: the removing admin compacts first, and the removal carries 32 bytes per message the removed device wrote that nobody has compacted yet. For data nobody ever compacts, that grows (3 MB at 100,000 messages), and removal fails past about 240,000 until someone compacts.
Recommendation: accept, with the number written down.

## 4. A hostile writer's own map key surviving a purge
A hostile writer can make one of their own map keys (for example a field named "secret") still show up, empty, after their data is purged. Honest writers never cause this. Removing that writer, or deleting the entry or the map, still clears it.
Options: write it down as a known limit (recommended; no code), or make an entry show only while its creation is held. That closes it fully, but a deleted entry could then no longer come back when someone else edits inside it.

## 5. A device offline past a disappearing value's end
Today: you already said devices may differ when a value ended before a device could apply it, but the requirements don't say so, and the fixes keep adding rules.
Proposal: write it down. Such a value counts as never received on that device. It may show the value from before until someone next compacts that data. The expired value itself never shows.
Recommendation: accept. A disappearing edit that replaced something could briefly show the old thing on a device that was offline the whole time.

## 6. Something added inside a disappearing entry
Today: if an entry in a map disappears at a set time and someone adds a lasting write inside it, one device may show the key and another not, for good. Rare (about 1 test seed in 1000).
Proposal: anything written inside a disappearing entry disappears with it. So a lasting reaction on a disappearing message disappears with the message.
Recommendation: accept. It is one rule and closes 3 issues.

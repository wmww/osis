# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2.

## 1. Changes that touch two things (answered in part)
Tess: keep atomic multi-thing commits; make them whole instead: every label a commit touches carries the whole commit, and purge, expiry and keep-at-most act per commit (or multi-thing commits are not purgeable). Design in progress (notes/whole-commits.md); it comes back for an explicit go before building.

## 3. Cost of removing someone from a group with long history
Requirement: removing a member never costs more as history grows. Today a removal lists every write of the removed device that stays valid, 32 bytes each. Old writes a snapshot has replaced need no listing, so compacting first (writing a snapshot of the current state) empties the list for ordinary data.
That does not help data kept forever, which is what chat messages are: those can never be replaced by a snapshot, so they are always listed. Kicking someone who sent 100,000 messages carries 3 MB, and past about 240,000 messages the kick fails, for good until something changes.
Options: accept and write down the number (a person rarely sends 240,000 messages, a bot might), or build the unbuilt second format (notes/frontier-study.md), which lists one short entry per device instead for data kept forever and meets the requirement.
Checked (notes/kick-cost.md): a simpler version of the second format works. For data kept forever, a removal lists one short entry per app launch in which the removed device wrote, instead of one per message: a few KB a year per device even for a heavy chatter, and no failed kicks. Writes carry nothing new. About 900 lines, half of it tests. The one-entry-per-device version you picked earlier turns out to need the same per-launch bookkeeping to stay safe against forgery, so it can come later as an optimization.
Recommendation: build the per-launch version. Plus a backstop: past the size cap, the newest unlisted writes are left out and reported, rather than the kick failing.

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

# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2.

## 1. Changes that touch two things (answered in part)
Tess: keep atomic multi-thing commits; make them whole instead: every label a commit touches carries the whole commit, and purge, expiry and keep-at-most act per commit (or multi-thing commits are not purgeable). Design in progress (notes/whole-commits.md); it comes back for an explicit go before building.

## 3. Cost of removing someone from a group with long history
Requirement: removing a member never costs more as history grows. Today, on data kept forever (chat messages), a removal lists every message the removed device wrote: 3 MB at 100,000 messages, and it fails past about 240,000.
Your idea, checked (notes/kick-dag.md): each keep-forever write names the newest writes it saw (35 bytes each); a removal names the newest write(s) the remover had; a write counts if the "I saw these" chain reaches it. Nothing made after the removal can be reached, so it is forgery-proof, and the cost is one entry per aspect however the member wrote. One added rule: a writer only builds on writes whose whole past it holds (else a removed member could publish a stash of pre-written messages afterwards).
Costs: 35 bytes on every keep-forever write; each device walks the chain once per removal (about what a removal already costs it); a device that gets the removal before the writes it names treats the member's history as invalid until they arrive. About 1800 lines, half tests.
The per-launch alternative (notes/kick-cost.md, 900 lines) lists one entry per app launch, which for a CLI is one per message, so it does not meet the requirement.
Recommendation: build your chain version.

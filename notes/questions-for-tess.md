# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2.

## 9. Group members can see each other's device lists
Today: when a group's key changes, everyone in the group receives every member's device list and each device added or removed (a side effect of how a key change proves it shut out removed devices). It also grows: about 150 KB per key change for 1,000 members.
Options (notes/roster-names.md):
1. A new proof scheme ("descent": each new key signs that it follows the old one). Fixes both the leak and the growth; checked in our model of key changes. About 1000 lines.
2. Small fix: still send the proof, but strip the device list down to the bare minimum it needs. Closes most of the leak; the growth stays.
3. Leave it.
Recommendation: 2 now (small, closes most of the leak), 1 later if big groups make the growth matter.

## 10. Keep-at-most: keep only 0
Today: keep at most is "0 after replaced" (purge on replace: the replacing node drops the old body at once and deletes it at hosts), "D after replaced", or an absolute time T (spec/commits.md §5). The D and T forms need each node to date deaths and drop on its own date, and host deletes timed at the bound: part of the arrival-order bug stream (notes/order-study.md option 5: closes 3-4 of its 22 issues). With no keep bounds, compaction already may drop covered old versions whenever it runs, so D and T add little: recovery windows are keep at least D, storage cleanup is the default, a value with an end date is expiry. Chat uses none of them.
Options:
1. Keep at most only as 0 after replaced; drop D and T. Keep at least (relative included: it only delays drops) unchanged.
2. Leave it.
Also: keep at most 0 is allowed only under `writer`, so chat edits purge explicitly instead (notes/chat-designs/e-evidence.md); allowing it under `author` would let chat use it.
Recommendation: 1.

## 11. Moving a thing without its history
Today: moving a thing to another owner copies it with imported history (spec/permissions.md §7): imported writes keep their original authors, purge rights and retention. 29 merged items touched imports (purge-imports took two reviews; import-own-source and import-body-never-live are open), and a whole order oracle (`purge_import`) exists for them. Requirements call moving rare; chat never moves.
Options:
1. A move copies the current values as new writes by the mover; the original stays with its owner. No import marker, origins or imported purge rights.
2. Leave it.
Recommendation: 1 unless an app needs original authorship or undo history across a move.

## 12. Kick cost on never-compacted data
Today: "Removing a holder costs ... one entry per aspect it wrote, never to content or history" (spec/requirements.md Cost) is not met: frontier-clobbers-history and frontier-certificate-cost need a second frontier format (notes/frontier-study.md F3/F4, unbuilt).
Options:
1. State the limit: a removal costs about 32 bytes per uncompacted commit the removed device wrote on keep-forever data; the remover compacts first when it can. Do not build F3/F4.
2. Build F3/F4.
Recommendation: 1 (notes/core-triage.md §2.3).

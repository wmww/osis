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

## 10. Keep-at-most D after replaced, and at time T
Today: keep at most is "0 after replaced" (purge on replace, prompt), "D after replaced", or an absolute time T (spec/commits.md §5). Keep at most 0 stays either way (values that must never have history). D and T are the only way to say "old versions kept a while, then surely gone" (moderation copies erased after 30 days, location history gone within a day, legal retention limits); with no keep bounds compaction may drop old versions but never must. Making D act only through compaction would make it pointless (that is the default), so the choice is keep or drop.
Options:
1. Keep D and T as guarantees. Cost: each node dates deaths and drops on its own date, plus host deletes timed at the bound (notes/order-study.md option 5: 3-4 of its 22 issues). Most of the arrival-order class comes from keep at most 0 and expiry, which stay either way.
2. Drop D and T; apps build "kept a while, then gone" from keep at most 0 on the value plus an expiring history copy written with each edit.
Also: keep at most is allowed only under `writer` purge rights, so chat edits purge explicitly instead (notes/chat-designs/e-evidence.md); allowing keep at most 0 under `author` would let chat use it.
No recommendation: close call; depends on how many apps want "kept a while, then gone".

## 11. Moving a thing without its history
Today: moving a thing to another owner copies it with imported history (spec/permissions.md §7): imported writes keep their original authors, purge rights and retention. 29 merged items touched imports (purge-imports took two reviews; import-own-source and import-body-never-live are open), and a whole order oracle (`purge_import`) exists for them. Requirements call moving rare; chat never moves.
Options:
1. A move copies the current values as new writes by the mover; the original stays with its owner. No import marker, origins or imported purge rights.
2. Leave it.
Recommendation: 1 unless an app needs original authorship or undo history across a move.

## 12. Kick frontiers: one system or two
Today (built, F2): a kick lists commit IDs, leaving out what the demoter's compaction could drop now. On keep-forever data (chat messages) that lists every kept commit of the device: 32 B each, about 3 MB at 10^5 messages per label it is re-encrypted under, refused past about 1.9e6 (`MAX_LIST_BYTES`). Approved earlier: the per-aspect hash DAG (notes/kick-dag.md), for permanent data only, so two systems. Tess (later): does not love two systems; maybe IDs in every case unless the DAG is quite simple (about 1800 lines, half tests, 35 B on every permanent write).
Options:
1. IDs only. State the kick-cost requirement (spec/requirements.md Cost) as a limit with the numbers above; delete kick-dag, kick-cost and frontier-study F3/F4 plans; keep ID batches (notes/frontier-study.md §11) as the fallback if costs ever hurt (additive, one system).
2. Build the kick DAG as approved.
Recommendation: 1; batches if measured costs need it.

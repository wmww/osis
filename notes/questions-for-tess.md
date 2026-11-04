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

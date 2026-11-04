# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2. The two below: notes/keys-requirements-study.md.

## 1. Should timed shares and self-removals count as key departures?
Today, when a timed share ("until") passes or someone leaves on their own, the next writer of the group must rotate its keys before writing, judged by its own clock. It is the one place keys depend on wall time; it needs a drift guard on re-seals and two exceptions, and the requirement already says such a removal "cuts off nothing by itself".
- **A (recommended):** they are not key departures. Reading of new content ends when a device of a sharer or admin writes an explicit removal after the expiry (links already do this; plain timed edges get the same finalizer). Loss: a timed guest keeps reading new content until that device is online after the expiry.
- **B:** keep as is.

## 2. How far should a group's keys look inside its member actors?
Today, when a device leaves a person, every group the person reads must learn of that exact departure (names in history boxes and on grant boxes, bound seals, placed revokes) before any writer uses the group's keys. It is the largest machinery in the system, its review has not happened, and it is what leaks member rosters to every reader (the open privacy issue).
- **A (recommended):** a group seals to a member's current keyset and rotates when that keyset is superseded; it never learns who left the member. Protection against departures inside a member is then only as good as the member's own keyset: if a sibling device rotates the person without knowing of the removal, or the removed device forges the person's keyset while the removal is withheld from the group's writers, the removed device reads the group's new content until the person's next knowing rotation. Today those same rare cases lock the whole person out of the group instead. Direct removals from the group are protected exactly as today. Deletes about 2k lines and three open issues; needs a short model check before building.
- **B:** keep as is (then the redesign's review and the roster-privacy fix stay on the list).
- **C:** keep the machinery, cap the nesting depth: deletes almost nothing, the cost is at depth 1.

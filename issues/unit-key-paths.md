# Must a role held through a group work when the group itself is not referenced?
> Summary: With one unit per independent thing, a node uses a role through a holder (a group, an org) with what it finds in that holder's unit. Where the closure references the holder that is free; where it does not, the role does not count for that closure. The alternative (a reference naming the holders on its way, "key paths") was modelled and does not deliver what it was for. Tess: confirm the simple rule, which the plan builds, and its clause in spec/requirements.md.
> Priority: low
> Tags: tess-call, sync, engine, spec

## The question
Your account is a member of group W. W can read document D. Your home references D directly, and nothing you hold references W. Must D sync to your nodes, and to a node keeping your data unread?

Today it does for nodes that read: a group's role records are copied under every unit above it. That copying is among what the new unit removes, and it never served a node keeping data unread.

## The two rules
1. **A role through a holder counts while you hold the holder.** D syncs once something you hold references W (you follow the group, or it is the realm D sits in), or you are granted a role on D yourself. Otherwise your reference to D is "not carried", with the existing warning.
   - Cost to users: the corner above. Sharing a set of things through the thing that references them (a realm and its documents) is unaffected.
   - Build: nothing beyond the walk.
   - spec/requirements.md Data model says a thing takes with it "the part of its closure it can itself sync". If "can itself sync" includes roles through any chain of holders, this rule narrows it and the item needs a clause.
2. **The reference names the holders on its way** (key paths). Whoever writes or later sees the reference, and can see the grants, records which holder units lead to D; nodes open those units for their keys only. Modelled (notes/closure-model.md, Finding D, Finding E):
   - It does not keep the requirement under the wider reading: a chain held by the root and not by the referrer, or a better chain beside a direct grant, still does not count.
   - Two nodes on different sides of a dispute over a grant on the path log and delete the path without end.
   - It needs data only some writers of a unit can write or check, which the unit design otherwise has none of (notes/sync-unit-design.md §2): a path can be missing because nobody who knew wrote it, and a forged one can stay.
   - A node keeping your data unread learns which opaque units sit between two of its units.
   - How often the corner arises: in the model's family of three independent things with every grant of none, sync or read and 8 candidate strongs, the root's role over any chain exceeds its role through units of its closure in 18738 of 186624 worlds.

## Recommendation
Rule 1, with the clause in the requirement, and drop rule 2 as designed: it fails the cases it was for and brings back the faults the unit design removed. The case is unusual, the warning exists and the way out is cheap. A design that made every chain count would have a node open, for keys, every unit its things were granted anything on, referenced or not: work and storage in grants, not in references.

## Meanwhile
The plan (notes/redesign-plan.md, M1, B1) builds rule 1 and no key paths (notes/sync-unit-design.md §4). If Tess wants chains through unreferenced holders to count, that is a new design, not a switch.

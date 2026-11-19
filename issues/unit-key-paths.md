# Must a role held through a group work when the group itself is not referenced?
> Summary: With one unit per independent thing, a node uses a role through a holder (a group, an org) with secrets it gets from that holder's unit. Where the closure references the holder that is free; where it does not, the reference must name the holders on the way (a "key path" in the member blob, notes/sync-unit-design.md §4) or the role does not count for that closure. Tess: keep key paths, or accept the simpler rule. The plan builds the simpler rule first.
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
2. **The reference names the holders on its way** (key paths). Whoever writes or later sees the reference, and can see the grants, records which holder units lead to D; nodes open those units for their keys only.
   - Cost: a new state for a unit (held for keys, nothing stored, not followed), a part of the member blob that only some writers can judge, and a node keeping your data unread learns which opaque units sit between two of its units.
   - Does not keep the requirement under the wider reading: a chain held by the root and not by the referrer, or a better chain beside a direct grant, still does not count (notes/closure-model.md, Finding D); and it loops under forked sides over a path grant (Finding E).
   - How often the corner arises: in the model's family of three independent things with every grant of none, sync or read and 8 candidate strongs, the root's role over any chain exceeds its role through units of its closure in 18738 of 186624 worlds.

## Recommendation
Rule 1, with the clause in the requirement. The case is unusual, the warning exists, the way out is cheap, and rule 2 is the costliest piece of the unit design for what it gives.

## Meanwhile
The plan (notes/redesign-plan.md, M1, B1) proceeds on rule 1. Rule 2 is additive: one more field in the member blob and one more state in the walk, B1's last brief, built only if Tess keeps it. Nothing built on rule 1 is undone by adding it.

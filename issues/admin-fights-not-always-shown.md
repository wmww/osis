# Admin fights are not always shown as disputes
> Summary: When admins of one thing lower each other at the same time, every node reaches the same result and a node trusting one side reads safely, but which admin wins can turn on a third party's write that ends up doing nothing, and a node trusting none of them is not always told a fight happened; spec/requirements.md says a dispute is reported: must that hold for every fight?
> Priority: low
> Tags: tess-call, perm

**What happens.** When two or more admins of a thing remove, demote, or put an end date on each other at about the same time:
- every node holding the same writes and trusting the same side reaches the same result;
- a node that trusts one of them (the one whose removal it sided with) gets the safe reading: a stolen key or a removed party gains nothing;
- but which admin wins can depend on a third party's write that, in the end, applies nowhere; and a node trusting none of them is not always shown that a fight happened.

**How often** (the write-path model, roles-model `paths`, as counted, not failing): in 1,000,000 small random worlds about 47 such cases (2 with invites); in 400,000 stolen-node story worlds 1,355 readings, 1,254 of them at nodes trusting nobody (where the thief's own do-nothing writes always tipped it toward the honest remover); with honest writers only (no thief, each list honest, each clock honest) about 9 in 1,000,000. Every case checked is a fight among parties who each held admin at their write; none lets a made-up key or a party removed earlier gain anything at a node trusting the removal.

**The smallest honest case** (notes/path-model-findings.md 36):
1. H makes B an admin.
2. B gives H's admin an end date, then makes Z an admin.
3. Z, seeing all that, makes H an admin again.
4. H, having seen only Z's grant, removes B.
5. With Z's grant held, H's removal works: B and Z lose admin and H stays; without it, H's admin had ended, so B and Z stay admins and H has none, and in neither case is a dispute shown.

**The question.** spec/requirements.md (Permissions) says a node reports a dispute. Must that hold for every fight among admins, or only where a node's trust decides the reading (where it now holds)?

**What the plan does meanwhile.** It proceeds as modelled: the walk judges each lowering once and keeps that verdict, and these cases are counted, not gated. Next, the model treats a write that ends a standing admin by an end date as a lowering at that date (notes/a1-spec/README.md, Open 13), which is expected to show finding 35's and 36's cases as disputes; the counts it must beat are above. The other way to close it, re-walking until nothing changes so a verdict can be taken back, was modelled and breaks safety (finding 16).

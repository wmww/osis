# Addenda duty as a memo over its inputs
> Summary: `flows/addenda.rs` keeps "what a node owes for removal R" fresh by hand-kept triggers (notes/engine-roles.md, Addenda: the inputs table); a missed one is an addendum never written. Make the decide an `osis_base::memo::Effects` value per removal so a changed input wakes it by construction; needs perm to stamp the decide's reads finely enough that the addenda cost tests still hold.
> Priority: normal
> Tags: engine, perm

**Why.** Each trigger of the addenda duty is code someone remembered to write. A missed one is an addendum never written: an honest write the remover missed falls for good at every node.

**Design.** Split the judgement as today: the gathering (whether R applies, its candidates) and the decide (`owed`: this node's roles, its own counting addenda, the node closure). Keep the decide's answer in an `Effects<CommitId, Owed>` (`osis_base::memo::Effects`: `settle(r, f)` records every stamped read, `due()` gives the removals whose reads moved, in proportion to the writes since). The due set becomes `Effects::due()` plus the gathering's own triggers. A read the debug `Checks` finds unstamped is a bug, found by construction rather than by a seed.

**What blocks it.** The decide reads the thing's `Timeline` (`role`) and the counting addenda on the thing, each one value per component or thing: any role commit there (a removed party's junk included) would move every removal filed there, breaking the addenda cost tests (`apply::tests_addenda`). Perm needs to offer stamped reads of one party's role on one thing at a point, and the counting addenda per (writer, removal). With those, the decide's reads are as narrow as today's triggers, and the gathering (whose reads are the walk before R) can follow (issues/addenda-wake-cost.md wants a per-removal change report too).

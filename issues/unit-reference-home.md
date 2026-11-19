# May a reference typed in from a bare ID fail to bring a thing that lives inside a realm?
> Summary: A strong reference to a dependent thing brings that thing's unit (Tess). For every node holding the referrer to agree on which unit, readers and nodes keeping it unread alike, the reference's writer records the thing's home beside it. A writer that never held the thing, and copied the reference from nowhere that knew, records none, and that reference brings nothing by itself. The plan proceeds on accepting this corner; spec/requirements.md Data model would gain a clause.
> Priority: normal
> Tags: tess-call, sync, engine, spec

## The question
A page X lives inside a realm H (dependent: it shares H's keys). You add X to your own list G. Your nodes, and a node keeping your data unread, should then sync H's unit, since X is in it.

Nothing about X's ID says it lives in H. So whoever writes the reference notes "X, found in H" beside it (the home, notes/sync-unit-design.md §2), which any node that holds X can do, and which travels when a reference is copied from a thing the node reads. An app sees no difference: a reference is still just the thing's ID.

The corner: a reference written from a bare ID (typed, pasted, from another system) by a node that does not hold X and has no reference to copy. It has no home. May it bring nothing until X is reached some other way?

## The answers
1. **Yes: a reference with no home to a thing that is not shared on its own brings nothing by itself.**
   - A user sees: paste the ID of a page inside a realm you can read but have not opened on this node, and the page does not sync until you open the realm (or the reference is written again by a node that holds the page). The existing "not carried" warning shows. A thing shared on its own (independent) is unaffected: its ID is enough.
   - Requirement: spec/requirements.md Data model, "a thing takes with it ... the part of its closure it can itself sync", gains "where the reference says where its target lives, as it does whenever its writer held the target".
   - Counted in the model's small family (notes/closure-model.md, The join): were no reference to carry a home, the walk would enter less in 4193 of 26661 worlds; with homes written wherever the writer held the target, the corner is only the bare-ID write.
2. **No home at all**: a strong to a dependent thing never brings its unit; only a thing shared on its own is brought by a reference. Reverses "a strong to a dependent thing brings its independent's unit" (issues/sync-unit-dependent-tree.md, Answered). Simplest build: one field less.
3. **Every reference works whoever wrote it**: each unit announces, to nodes keeping it unread, an opaque handle for every thing inside it. Costs an entry of about 400 B per dependent thing in every unit (spec/requirements.md Scale: millions of things never shared directly), shows such a node how many things a unit holds, and a node must still search the units it may enter for the one announcing the handle.

## Recommendation
Answer 1. The corner needs a node to reference a thing it has never held, by an ID from outside osis, and the way out is opening the realm once. Answer 3 pays per thing, everywhere, for it.

## Meanwhile
The plan (notes/redesign-plan.md, M1, B1) proceeds on answer 1. Going to answer 2 deletes the home; going to answer 3 adds a blob class and a search. Neither undoes anything else built.

## Kept apart from the question
Where the home is written is the design's choice, not Tess's: beside the value in the delta (planned; a reference stays one plain value), or inside the reference value (simpler to carry; two references to one thing then compare unequal, which an app would observe, against spec/requirements.md API). notes/redesign-plan.md risk 8 says when the plan would switch.

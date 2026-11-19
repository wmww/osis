# A dependent holder serves readers only
> Summary: Under the sync unit design a node keeping a unit unread uses a grant held by a dependent thing of that unit only until the target's next rotation, while a reader keeps it. The state arises only after a promotion judged invalid below a promotion that stood. The property that holds is the weaker one below; an admin making the holder independent again (spec/permissions.md §3 SHOULD) restores the strong one.
> Priority: low
> Tags: sync, engine

## The state
Y holds a grant (its mint-admin record edge, or any grant with key access) while Y is a dependent thing of K's unit. spec/permissions.md §3 makes a thing independent before it holds any grant, and makes a dependent mint admin independent before its thing is. So the state needs a grant that was made while Y was independent and Y's promotion judged invalid later (spec/crypto.md §3: "a thing whose only such part turns invalid is dependent again").

Smallest world (held-model `spec_unit::an_invalid_promotion_leaves_a_dependent_holder`): H, X a dependent of H, Y a dependent of X, H -> X -> Y. X is promoted, then Y (its mint admin is now independent). Then X's promotion is judged invalid: X is H's again and Y stays independent, X on Y's step. S(H) holds Y's key and handle (X is of H's unit).
- A reader of H knows X's tid, derives X's sync secret from H's, and keeps Y.
- A node keeping H unread knows no tid of H's dependents. It enters Y only by the key blob's first credential (Y's sync secret as the logger held it) and loses Y at Y's next rotation, with Y's content.

The general static form (`p2_a_dependent_holder_is_entered_by_readers_alone`): wherever a step lists a dependent holder, a keeper and a reader of the same root enter different units.

## The property that holds
Instead of notes/sync-unit-design.md §3 "a reader and a node keeping the same roots unread enter the same units always":
- They enter the same units whenever no step they meet lists a dependent thing.
- Where one does, the node keeping the root unread holds the target from the key's first credential until the target rotates, and not after, until an admin of the holder makes it independent again (spec/permissions.md §3: an admin node seeing a dependent thing holding a role with key access SHOULD make it independent). The model shows the re-promotion giving the keeper the target back.

## Cost
Availability only, for nodes keeping the closure unread: between the target's rotation and the holder's re-promotion they hold none of the target's new content, so a reader relying on them for it waits for a reading peer. Nothing is shown to anyone who could not read it before.

## Ways out, if the weak form is not enough
- A step lists a dependent holder by its independent's claim instead (the unit's own sync secret opens it). Then a node keeping K unread enters everything a dependent of K was granted: it follows the unit, which is what the walk already assumes.
- Leave it: the state needs an invalid promotion under a valid one, and the SHOULD of spec/permissions.md §3 repairs it.

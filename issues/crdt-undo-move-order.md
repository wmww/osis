# Undoing a move can reorder siblings
> Summary: The restored position write is the newest child of the old anchor, so after undoing a move an element can land before a sibling it used to follow (list `[2,1,0,3,3]`: move, undo gives `[2,1,3,0,3]`); spec §4.6 does not promise exactness for moves, and the model differential (crdt tests_undo.rs) skips moves in its exact-restore check.
> Tags: crdt

Found by the reference-model undo differential (branch commit-query). Both the implementation and the model behave so; a fix needs a position write that sorts among the anchor's children where the element was (§6.1 sibling order), or the spec stating undo of a move is approximate.

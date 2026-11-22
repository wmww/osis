# A reset re-dates every earlier body of its aspect
> Summary: On a dated aspect, a write that resets a whole value (a text written whole by `Replace`) makes `date_due` judge every earlier body again, each O(its part), though at most one row moves: the history's dating cost grows with the square of its length.
> Priority: normal
> Tags: engine

`ByWrite::moved_by` (notes/engine-retention-dating.md Rows) returns, per position at or below the new write's, the greatest held write stamped no later. A reset at the root reaches every position the aspect ever held, and each old element's creation is owned by a different earlier body, so `moved_by_joins` hands `date_due` every earlier body, each judged by `index_date` (a winners walk of the whole part, plus the debug `whole_date`). Those bodies were already dead by an earlier reset, so a later superseder cannot move their date.

Measured in `undo::tests::check_cost` shape `whole` (text written whole each commit, kept until a date): judgments (`replaced at`) over the history are 81, 234, 5154, 20304 at n = 10, 20, 100, 200 (about n²/2), against n rows moved; the other shapes judge about n. The undo check itself stays flat.

Wanted: an add-only transaction judges O(what its writes newly supersede). A candidate whose earliest superseder is already stamped before the new write cannot move, but finding the candidates is still a walk of every position under the reset: the fix is likely an index of the not-yet-superseded writes per position (the frontier the new write can still date), not a filter on `moved_by`'s output.

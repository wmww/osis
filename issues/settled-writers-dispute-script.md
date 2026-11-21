# A settled-history test's scripted dispute reaches nothing
> Summary: engine `order::settled_writers_fetch_what_their_first_side_dropped_before_compacting` (ignored) plays a hand-written dispute that no longer makes 2's register write "v5" stand at the keep-everything node (it reads "g"), on main as on the needed-by-reference rule, so it checks nothing; it needs a new script (or a constructed setup) reaching its case.
> Priority: low
> Tags: engine, tests

Stage A1 (notes/redesign-plan.md): the dispute it plays is the walk's; check it against the rebuilt walk before rewriting.

Its case (spec/commits.md §5 Invalid): 2 writes G's register while 0 and 2 dispute their roles; writers 0 and 1 drop the write on their first sides, on the walk's side it is valid again and missing, and `settled` fetches before compacting, so a node given the history newest first and the compactions last reads "v5" as the keep-everything node does. Since `NewTop` things are shared (`share_top`, every peer reads them) the script's `RemoveFlow`/`Demote` targets no longer make that dispute: its `Undo { by: 0, back: 0 }` is refused (`only content commits are undone here`), and every variant of the `RemoveFlow` and both `Demote` targets over things 0..7 leaves the keep-everything node reading "g". Rewrite it as a constructed history (notes/principles.md, Never pin a seed) that reaches the dispute by construction.

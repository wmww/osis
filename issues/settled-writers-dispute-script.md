# A settled-history test's scripted dispute reaches nothing
> Summary: engine `order::settled_writers_fetch_what_their_first_side_dropped_before_compacting` (ignored) plays a hand-written dispute that no longer makes 2's register write "v5" stand at the keep-everything node (it reads "g"), so it checks nothing; rewrite it as a constructed history reaching its case (notes/principles.md, Never pin a seed).
> Priority: low
> Tags: engine, tests

Its case (spec/commits.md §5 Invalid): 2 writes G's register while 0 and 2 dispute their roles; writers 0 and 1 drop the write on their first sides; on the walk's side it is valid again and missing, and `settled` fetches before compacting, so a node given the history newest first and the compactions last reads "v5" as the keep-everything node does. Since `NewTop` things are shared (`share_top`) the script's `RemoveFlow`/`Demote` targets no longer make that dispute, and its `Undo { by: 0, back: 0 }` is refused.

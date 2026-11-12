# A piece entry reported after its freed link left the set is never judged
> Summary: Unverified, from the tomb-all review (restated for freed sets). A piece is deleted at hosts through the freed set (spec/sync.md §7 Freed links), and its link leaves the set once the node knows no entry of it. A host reporting the entry again afterwards (an upload answer lost, within the piece's tombstone or past it) gets an entry no pass judges: the host keeps the copy and the node keeps its entry and presence row for as long.
> Priority: low
> Tags: node, sync, growth

Bounded by the host's copy (one per lost answer of a piece freed here); the window needs the host away while the link is judged and deleted elsewhere. Options: keep a freed link while a tombstone of its entry stands (rows for `TOMBSTONE_LIFETIME`), or accept it as a stated host leak.

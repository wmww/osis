# A chunk at a host whose commit this node forgot is never judged
> Summary: Unverified, from the tomb-all review. A chunk entry is judged for deletion only through a commit header that lists it (`chunk_entries`, `dropped_chunks`). `forget_own_covered` waits for the commit's own body tombstones (`deleted`) but not for its chunks' tombstones, so a host reporting a dropped chunk (an upload answer lost) after the commit's header is forgotten, inside the chunk's tombstone or past it, gets a chunk entry no pass judges: the host keeps the copy and the node keeps its entry and presence row for as long.
> Priority: low
> Tags: node, sync, growth

Bounded by the host's copy (one per lost answer of a chunk whose delta is covered and dropped); the window needs the host away for about `TOMBSTONE_LIFETIME`. Options: count a chunk tombstone of the commit's chunks in `deleted_commit`, or accept it as a stated host leak.

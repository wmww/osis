# A listing anew fetches again a body the reader dropped
> Summary: A new reader that fetched a body and dropped its entry at once (no tombstone) fetches it again from any source that still lists it when S is pulled from the start (the raise to read); `first::a_blob_is_fetched_once_whatever_sync_ids_carry_it_spec_sync_streams_4` fails on branch windlass-pull-cursor by this, main passing it only because the maker's Delete reaches the other source first.
> Priority: normal
> Tags: sync, tests

Seen in the first:: closure world (`cost(LARGE)`, node 2 granted read; trace `OSIS_SYNC_TRACE=0,1,2:B612c17`): node 2 fetches an entry of the root's sync ID from node 1, its stream then shows `Deleted` of it in the same step (taken and removed: the maker had dropped it, node 0's listing showed its deletion), then node 2 is raised to read (`Register`, a join from the start), node 1's listing still shows the entry, and node 2 fetches it again and removes it again. On main the same take-and-remove happens; node 1 has applied node 0's `Delete` before node 2's listing anew, so it is not listed. On windlass-pull-cursor caught up waits for the Applied of every message served (a Pull reports nothing), node 0's Delete goes later, and the listing anew finds it.

What is wasted: one fetch per such body per listing from the start of a source that still holds it. Bounded (listings anew are rare), but a must-not-hold body never leaves a mark that stops the next fetch (spec/sync-streams.md §4 Bodies: only no entry and no tombstone count).

To settle: whether a reader's drop of a pulled entry it judged not to keep should leave something that a listing's announcement of the same entry is checked against (the engine still knows the blob's commit), or whether the first fetch should not have happened (node 0's listing showed the deletion before node 2 fetched from node 1).

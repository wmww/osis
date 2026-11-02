# A true part kept out by a copies flood is not fetched again by node-sync
> Summary: `apply::copies` keeps differing copies of a part or signature that cannot be checked yet, up to `MAX_COPIES_BYTES` a commit. Past that a later copy is refused, even the true one. The record's arrival frees the room and the engine takes the part when it comes again, but node-sync opens an entry once, so nothing delivers it again. On a thing the node syncs the commit then waits for that delta.
> Tags: security, sync, engine

Needs a reader (only those can write commit plaintext under a label) sending 16 MiB of junk under one signed header before the true part, with the thing's record away. Test of the engine half: `parts::copies_flood_evicts_nothing_spec_commits_4`.

Fix sketch: when a commit pends for `WaitDeltas`, node-sync ingests again the held entries of that commit whose `Kind::Commit` parts list a missing delta (`engine.blob`, as `genuine` reads them). Entries judged `Bad` are left out, so the work per pass is bounded by what the label lists.

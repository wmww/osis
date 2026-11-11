# expiry-strands
> Summary: Footguns met while moving the subgroup-cut `NotSynced` report into the engine.

- Diagnostic dedup (`Events::diagnostic`, key kind+commit+tids, no detail) silently swallows a second `NotSynced` for a thing told of once before (placed node-local, later synced, then stranded): the first test draft looked like the fix did not work.

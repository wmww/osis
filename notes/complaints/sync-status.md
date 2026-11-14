# sync-status complaints
> Summary: workflow notes from building the status module.

- The scratch dir named in a backgrounded command's redirect must exist first: the redirect fails silently inside the subshell and the run reports exit 0 with no output.
- `Effects` follows only stamped reads made inside `settle`'s closure: a value read just before it (a source list cloned out to pass in) is not followed, and the key never moves on it. Read every input inside the closure.
- A stamped container created after a reader looked (a new `Place` in streams) is invisible to that reader: the reader saw only the map's absence, which is not stamped. Status relies on streams' per-connection stamp moving at the same time.
- Review: the streams test Pair joins one side at a time; a member joined at one side whose Pull lands before the other side's join is answered "not shared" and never pulled again, which is not opens' order. A random-history test must join both sides at once.
- Review: a reader's held entry is the engine's (`Table::opened` in streams tests), not the store's; checking `Store::entries` for what a reader holds finds only its own.

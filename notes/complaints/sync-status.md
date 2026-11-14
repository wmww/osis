# sync-status complaints
> Summary: workflow notes from building the status module.

- The scratch dir named in a backgrounded command's redirect must exist first: the redirect fails silently inside the subshell and the run reports exit 0 with no output.
- `Effects` follows only stamped reads made inside `settle`'s closure: a value read just before it (a source list cloned out to pass in) is not followed, and the key never moves on it. Read every input inside the closure.
- A stamped container created after a reader looked (a new `Place` in streams) is invisible to that reader: the reader saw only the map's absence, which is not stamped. Status relies on streams' per-connection stamp moving at the same time.

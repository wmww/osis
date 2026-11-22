# review-death-dates
> Summary: Workflow notes from reviewing and gating death-dates.

- `tools/bin-at` for the lib and `it` of one crate is two full checkouts and builds (about 7 min here), then the branch rebuilds: a spare worktree on the base would have built both at once while this one stayed usable.
- Single-threaded `tools/icount` of osis-engine's lib and `it` take 3-6 min each; four at once in parallel is the cheap way.
- The crdt-level `moved_by_check` does not need `s` itself in `moved_by` (its generators make no differing copies of one write); only the engine's tests catch that plant (through `carried`). A check passing a mutant is a generator gap worth knowing before trusting it alone.
- The gate's first NEW (a crdt coverage floor) failed on main too at that offset; recording it took a spare worktree, an issue, a known_failures line and a landing before this branch's verdict could be read, about 10 min of bookkeeping for a test the branch never touched.

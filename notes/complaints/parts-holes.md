# parts-holes (tiller-parts-holes)
> Summary: footguns met while fixing the per-part holes.

- `Engine::open` re-examines everything pending, so a load-time pass for pending state is dead code that a fail-without-fix probe shows. I wrote one and removed it.
- A test using `demoted_writer_of` gets a first snapshot holding the frontier's blobs: a second snapshot reuses them, so "blobs away" silently isn't. Filter that first pack out.
- Single-threaded `parts_differential` at default size is 4-5 min; fix-disabled probes across 10 mutations took 10 min. Worth a seed-range note if it grows.
- Reviewer: local keys have no registry: `y/` was taken by node-sync, whose load reads every row under it, and nothing says so at the engine's prefix list. Grep both crates before taking a prefix.
- Reviewer: a flood test past a bound must fill to the last bytes: 4 MiB copies stop short of it and leave room for the small true part, so its "refused" branch had never run.

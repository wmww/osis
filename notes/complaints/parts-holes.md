# parts-holes (tiller-parts-holes)
> Summary: footguns met while fixing the per-part holes.

- `Engine::open` re-examines everything pending, so a load-time pass for pending state is dead code that a fail-without-fix probe shows. I wrote one and removed it.
- A test using `demoted_writer_of` gets a first snapshot holding the frontier's blobs: a second snapshot reuses them, so "blobs away" silently isn't. Filter that first pack out.
- Single-threaded `parts_differential` at default size is 4-5 min; fix-disabled probes across 10 mutations took 10 min. Worth a seed-range note if it grows.

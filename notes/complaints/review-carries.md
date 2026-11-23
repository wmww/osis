# review-carries
> Summary: Mishaps met reviewing and landing mizzen-carries.

- Mutation runs queued behind other agents' gates for most of their wall time (each hold waited 1 to 15 minutes); a statement-level mutation (a removed call) cannot join a batch and costs its own engine build.
- Four pieces of the branch failed no default test when undone (the mark's flush, both snapshot touches, `Facts::reads`' carries compare): reached constantly, but always beside a path doing the same work. A guard redundant in every tested path is invisible to mutation; a debug assert of the invariant (no pending touch at a rollback) would be what catches its loss.
- An `eprintln!` probe in a passing test prints nothing without `--nocapture`: one build wasted.

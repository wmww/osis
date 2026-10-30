# retention-simplify
> Summary: workflow notes from the retention-simplify simplification pass.

- The order harness's `alike` and the walks compare `Engine::index_digest` as text; changing an in-memory record's shape (`Meta::dropped`) meant hand-keeping the digest line format so `no_dropped`'s `{...}`/`gives=` slicing still works. A structured digest would make such refactors safer.
- Building old-vs-new release binaries in one worktree means swapping sources (`git checkout <base> -- core`) and two 2.5-3 min release links; a `tools/` helper that builds a base commit's test binary into scratch would save the dance.

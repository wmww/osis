# crdt-simplify
> Summary: Workflow notes from the osis-crdt review-and-simplify pass.

- `tools/wt claim` found wt1's target at 15 GB (stacked generations) and deleted it; the first `cargo test -p osis-crdt` was cold (about 50 s, fine for one crate).
- Finding dead public API took a script: rustc's dead-code lint does not see `pub` items no other crate calls, so unused API (`Fragment::placement`, `struct_skeleton`, the per-author un-merge) sat unnoticed. `grep -w <fn>` over `git ls-files '*.rs'` outside the crate per public fn worked.

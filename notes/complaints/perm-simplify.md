# perm-simplify
> Summary: complaints from the perm simplification pass.

- `cargo test --workspace --test it -- --ignored roster:: ...` (perm tier 2) took 7 min wall at this load, about twice the 3.6 min notes/testing.md quotes; most of it the one osis-perm binary (312 s).
- notes/permissions.md lines are single paragraphs of several KB: a `sed -n` range of 40 lines printed 68 KB; reading a section needs `cut`.

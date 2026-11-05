# libs-layout
- `wt` finds targets with `<wt>/*/target`, so `wt release` no longer prunes `libs/kit/target`. Needs `*/*/target` in the plugin (notes/build.md).
- The path sed read `kit/app` ("kit and app") as a path; check prose hits of a short word after a scripted rewrite.
- `git mv kit libs/kit` moves the ignored `target/` too, so no separate `mv`.

# derived-immutable
> Summary: Workflow notes from the derived-state step 1 branch.

- `tools/icount` on an osis `it` test varies about 5% run to run (thread timing moves the pass count): take three runs before believing a gain under 10%.
- A callgrind caller tree splits one function over the source files its inlined callees come from; match the `*` line by function name and ignore the rustlib rows.
- `cargo test -p osis` hit the direct-redeem stall once (issues/flaky-single-use-direct-redeem.md) on an unrelated change.

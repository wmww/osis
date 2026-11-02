# sync-oddities-review
> Summary: footguns met reviewing the sync-oddities branch.

- `cargo test --workspace --test it <module>::` filters across every crate's `it` binary and says ok with 0 tests in most: read which binary ran the test (a `-p osis` retry found them).
- An invariant the code states (`examine`: "every wait only ends as the held set grows") had no test reaching a new input of that wait: the parts differentials hide whole packs, never a part of a commit with a demotion around. Added `removed_author_differential`.

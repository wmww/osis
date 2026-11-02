# purge-rejudge
> Summary: Workflow notes from the purge re-judge branch.

- `order::` shrink takes minutes at 60 steps with no progress output; `OSIS_ORDER_SHRINK=0` first, then shrink. A shrink of a seed that also fails for another reason finds that one: replaying with the step's effect removed told them apart.
- `cargo test --workspace --test it <filter>` prints a `test result` per crate, and an order failure's message holds a 200-element list per line; a small script to blank `[n, n, ...]` lists made them readable. Worth having in the harness.

# long-aspect-review (tiller-long-aspect-review)
- The gate stops at clippy before tests: a clippy lint in a new test costs a whole re-gate. Run `cargo clippy --workspace --all-targets -- -D warnings` once tests are added.
- `cargo test --workspace --test it <filter>` prints a block per crate with `it` and the tail cuts off the failing one: use `-p osis-node --test it` when looking at a node test.
- `cargo test` takes one name filter before `--`; several go after it (first mutant script ran none).

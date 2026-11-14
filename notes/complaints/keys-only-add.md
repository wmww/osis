# keys-only-add
> Summary: Workflow snags met on the keys-only-add branch.

- `sealed_write` panics on `commit(...).unwrap().unwrap()` when the value written equals the current one (commit is `None`): a test writing the same value first gets an unhelpful `Option::unwrap` on `None` at flows.rs, not a message.
- A backgrounded `cargo test ... > log; echo exit $?` reports the echo's exit 0 to claudewait even when a test failed; read the `test result` lines.

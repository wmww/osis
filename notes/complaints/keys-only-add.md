# keys-only-add
> Summary: Workflow snags met on the keys-only-add branch.

- `sealed_write` panics on `commit(...).unwrap().unwrap()` when the value written equals the current one (commit is `None`): a test writing the same value first gets an unhelpful `Option::unwrap` on `None` at flows.rs, not a message.
- A test log redirected with `> file 2>&1; echo exit $?` reported exit 0 although a lib test failed under `--no-fail-fast`; read the `test result` lines.

# api-setrole-now
> Summary: Mishaps while replacing `SyncFirst` with `set_role`/`set_role_now` and removing recovery from the API.

- A regex pass that dropped `sync: SyncFirst::Skip` from test call sites silently turned "write at once" into "catch up first"; only a test with its node offline (hanging) showed it. Converting a mode argument away needs the call rewritten in the same pass, not the field dropped.
- `cargo test --workspace` stops at the first failing test binary; `--no-fail-fast` to see every failure in one run.
- localhost CLI tests are `#[ignore]`d: `localhost::` by name runs 0 tests without `-- --ignored`.

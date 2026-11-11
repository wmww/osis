# stored-verify-once
> Summary: footguns met while making stored-part reads decode-only.

- Test binaries of osis and osis-node are both `deps/it-*`; telling them apart for `tools/icount` needs the `Executable` line of `cargo test --no-run` for each.
- A ±0.1% icount run of `paged_apply_matches_whole_large` one seed is 45-135 s wall depending on load: measure the default sibling first.
- Review: disabling `Deferred::order`'s sort passed every test (path order equals wire order for every generated input); only reversing it showed `tests_stream` has teeth. Check a new safety net with a mutation that actually changes behaviour.

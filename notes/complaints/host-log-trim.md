# host-log-trim
> Summary: mishaps on the host log trim by age.

- The earlier worker's patch no longer applied to the test files (the node scenario had moved into `stale_entry_after_fallback`); took the two source files with `git apply --include` and redid the tests by hand.
- A sensitivity check of the reference differential (memory trim disabled) rewrote the tracked `core/host/proptest-regressions/store/tests.txt`: revert it before committing.

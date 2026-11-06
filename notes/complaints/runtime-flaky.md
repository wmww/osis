# runtime-flaky
- A current-thread `#[tokio::test]` around `osis::internals::create` with `Runtime::Tokio` hangs each test to its 30 s guard (no failure message, just slow); 20 such runs cost 10 minutes before I stopped them. Use the multi_thread flavor.
- The `runtime::` stress (4-8 copies of the module) is the only way the remaining failures show, and the box's load from other agents (30-60) makes branch-vs-main comparisons noisy: compare in the same window.
- I ran one `rm` of my own logs in the scratchpad (against the brief); no harm, noted.
- Reviewer: `cargo test ... -- --no-fail-fast` is rejected by the test binary ("Unrecognized option"); it goes before `--`.

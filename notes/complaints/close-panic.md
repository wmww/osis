# close-panic
> Summary: mishaps met while fixing the close-time timer panic.

- At load 20-30 the panic hit 3 in 200 runs (1.5%), not 1 in 20: a "few hundred runs" baseline took 6 min for 200. Running the copied test binary in a shell loop beat a repeat knob (no cargo per run), but each run still costs about 2 s.
- The 061a90b fix was checked by a test whose failure rate is low enough that a 20-run loop passes most of the time; a backtrace (`RUST_BACKTRACE=1`, loop until the first failure) showed the real path within 16 runs.
- Review: the worker looped only the one test, alone. In its module (`runtime::`, as tier 1 runs it) the branch failed 4 of 4: removing the `quiet` gating brought back the panic on the `#[tokio::test]` runtimes of neighbouring tests, and the close test's panic hook counted every thread. Loop a flaky test both alone and with its module; filter a global panic hook by thread name.
- `xargs -P 6` over the copied binary did 300 runs in about 2.5 min at load 15-20.

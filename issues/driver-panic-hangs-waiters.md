# A panic in the sync driver leaves waiters with a deadline hanging forever
> Summary: `Net::timer` wakes the driver through its control channel to look at deadlines; when the driver task died of a panic the send goes nowhere, so `wait_synced`, `wait_until` and the port's waits never time out: a test hangs with every thread parked instead of failing (seen with the `acting cached` debug check, eph-unify-b2).
> Tags: osis, tests

Repro shape: any panic inside `driver::run_shared`'s step (a debug assertion in the engine did it) on a node under `Runtime::Own`; the test's `block_on(x.wait_synced(.., W))` sits past W forever, the tokio workers idle, no lock held. Stacks were taken with a downloaded gdb (`apt-get download gdb` plus its libs, extracted, `LD_LIBRARY_PATH`; attaching needs ptrace rights, so the binary ran as gdb's inferior and got SIGINT after a limit).

Wanted: a dead driver fails its waiters (`Network("sync stopped")`, as `blocking` already answers when the control channel is closed), e.g. `timer` on a failed send resolves the deadline's waiters, or the driver's end drains them. Then a driver panic fails the test at once with the panic in its output.

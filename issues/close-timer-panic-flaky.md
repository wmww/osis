# Close-time tokio timer panic still happens
> Summary: `runtime::close_while_driver_runs_no_timer_panic` (osis `tests/it/runtime.rs`, added with 061a90b) still fails now and then: an `osis-sync` thread panics "A Tokio 1.x context was found, but it is being shutdown" (tokio `time/entry.rs`) while a `Runtime::Own` database closes. 1 in 20 runs at load 14, once in a gate run; the branch it was seen on touched only osis-crdt.
> Tags: api, tests

Repro: `for i in $(seq 20); do cargo test -q -p osis --test it runtime::close_while_driver_runs_no_timer_panic || break; done` under load. The fix (driver polls no timer while a control message waits; `wait_until` arms its timer only for an unresolved waiter) leaves some other path that registers a timer after shutdown starts.

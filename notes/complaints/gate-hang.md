# gate-hang
- `settled_histories_keep_their_laws`' all-seeds floor ("no signal dropped past its bound") failed every one-seed replay; it was a fact about the generator, so it is one of `histories_reach_*`'s SHAPES. A grep found no other `into_inner() > 0`-style floor in core/test.
- The hang watch is tested with a fake `cargo` script on PATH (tools/gate_select_test.sh): cheap and quick (about 1 s); no real hung test needed.
- Review: a fixture-free way to prove a watcher kills an orphan is a fake cargo that `kill -9 $$` after backgrounding its "test"; without the subreaper that case hangs the selection test for the fake's whole sleep.

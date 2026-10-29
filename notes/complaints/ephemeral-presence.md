# ephemeral-presence
- `random_window_converges_large` names no seed when a run fails by message storm (the panic is in `Net::settle`); added an `eprintln!("seed ...")` per seed (visible with `--nocapture`).
- `Hub::closed` had no outputs, so changing it touched nine harness call sites across four crates (sim, osis, node, server tests); the sim's `notify_closed` is infallible while `hub_out` returns `Res`, so `hub_out` was split.
- `Net::restart_server` queues the closes; `advance` right after ticks the nodes before they see them, so they redial only on a later tick. Call `net.run()` between them.

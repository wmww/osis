# sync-client
- `ManualNet::run` moves the manual clock to every wake within an hour: a call that ran it to wait for its answer jumped simulated time (stall deadlines, pings). Calls now use `ManualNet::deliver` (queued inputs and wakes due now only).
- `Multi` refused every `unix://` dial, so a thin client could not reach its node's socket; only a real-socket test showed it (the test network dials by URL itself). Fixed with `Multi::unix_dial`, set for a thin client's scratch node alone.
- `tools/spec_map.py` reads `notes/x.md §N (anchor)` in a test comment as a citation of the spec file named before it ("stray anchor"): cite notes without `§N (...)`.
- osis's lib has `test = false`: a `#[cfg(test)]` module in src builds and passes under `cargo test -p osis --lib` but is a policy violation; the policy run at the end found it.
- Review: the rebase onto sync-rebuild applied cleanly but did not build (`Engine::labeled_groups` gone with the facade); a clean rebase is no sign the branch compiles.
- Review: `tools/spec_map.py --gaps --uncited` lists 23 stray anchors in core/sync tests this branch never touched (from sync-integrate-4): noise that hides a new one.

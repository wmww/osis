# The order harness writes no signals
> Summary: held-model judges signals without `+` (`Aspect::signal`, its properties and `spec_signals`), but the osis-node order harness never writes one, so no tier-2 oracle compares the engine's signal bodies (keep-bound drops, history, kicks) against the model in random arrival orders. Add an op on a `~` key with keep history to the harness and map it in `held.rs` (the adapter already reads the marker).
> Priority: low
> Tags: tests, node

The harness's ops share special cases a signal must skip: `Compact` (a signal is never snapshotted: `Engine::snapshot` refuses), `revert` (refused for a commit carrying a signal), path ops (a signal takes one root set). Engine coverage today is the targeted osis-node `signals::` tests.

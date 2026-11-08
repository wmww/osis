# The order harness writes no signals
> Summary: held-model judges signals without `+` (`Aspect::signal`, its properties and `spec_signals`), but the osis-node order harness never writes one, so no tier-2 oracle compares the engine's signal bodies (keep-bound drops, history, kicks) against the model in random arrival orders. Add an op on a `~` key with keep history to the harness and map it in `held.rs` (the adapter already reads the marker).
> Priority: normal
> Tags: tests, node

Normal, not low: until then held-model's signal rules are checked only against themselves, and the engine's only by the scripted osis-node `signals::` tests. The harness's ops a signal changes: `Compact` (`Engine::snapshot` of a signal is `None`), `revert` (writes nothing for a signal part), path ops (a signal takes one root set).

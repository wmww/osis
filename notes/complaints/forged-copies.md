# forged-copies
> Summary: Workflow snags met fixing the forged-copies state-differs seed.

- The engine's state-vs-rebuild check (`checked_states`) runs at drop/restart and compares the cache-free stored state; a probe reading `tx.state` sees the cache and reports "same" until the cache is removed. Probes comparing stored state must drop `core.states`/`core.pages` for the key first.
- A hand repro of an unreported join change passes when the aspect's first body is the one that sets up the state (another path writes it whole): the hand test needs an earlier body on the aspect.

# release-expiry-everywhere
- The reported case (entry kept at a host that cannot read L) did not reproduce: plain hosts sweep it. The real gap needed a node holding rows of a label it no longer syncs (a replaced label) plus a restart to drop its open connections; finding it took most of the task.
- First fix (the hub's sweep expiring every row) broke two unrelated node tests: the hub ticks before node sync's step, so a row went before the engine's expiry timers. The ordering dependency is stated nowhere in code; now in notes/serving.md.
- A probe holding two `hub_store().lock()` guards in one `eprintln!` deadlocked the test binary silently (0 CPU, no output); cost a 9-minute wait.

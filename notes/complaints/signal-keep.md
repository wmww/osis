# signal-keep
- LocalPeer hands packages over directly, so no tier-1 test reaches node-sync's must-hold judgment for a signal body held past its bound (`sync/pass/bodies.rs` `must_hold`); that change rests on review and the spec text.
- A tier-1 workspace run took about 6.5 min on a busy box, not the 2.5 in CLAUDE.md.
- Review: node-sync runs due engine timers before every step on the engine's own clock, so a node holding a signal past its bound never reaches a pass with a manual clock; the must-hold test checks `SyncEngine::verdicts` directly.

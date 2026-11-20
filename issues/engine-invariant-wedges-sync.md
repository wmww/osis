# A broken engine invariant on one commit stops the node, and spins it on reloads
> Summary: an engine `Corrupt` while applying a commit is a local error: nothing is lost (the commit stays unreceived or pending, retried), but a deterministic one stops the node for good: node-sync's streams step fails at every retry (after a restart the body is offered again and fails again), and one in a re-examination round (`Engine::run_taken`) owes a whole-store reload whose next round fails again, with `next_timer` due at once while a reload is owed: a reload loop, and no pending commit of that round ever applies. Loud and lossless, but one commit tripping any engine bug (or a forged one, if any hostile input reaches a `Corrupt`) wedges the node.
> Priority: normal
> Tags: engine, sync, security

What happens:
- Arrival: core/engine/src/sync/bodies.rs `open_entry_once` passes a local-class ingest error up (never `Opened::Bad`); core/sync/src/streams/pull.rs `take_body` takes nothing (no cursor passes the body) and the step fails at the next settle (`streams::an_owed_body_settles_only_once_taken_under_its_sync_id_spec_sync_streams_4`: refetched after a restart). Right for a transient store failure; for a logic invariant it repeats forever.
- Re-examination: `run_taken` (a `reexamine` round, `promote_loose`) failing for any reason sets `taken_failed`; the next transaction reloads as an open does and examines every pending commit (`Wake::Open`) in one round, so one commit whose examination errs rolls back the whole round again. `reload_owed` keeps `next_timer` at now: each tick reloads the store and fails. Arrivals not pending still apply (their own transaction), each after a whole reload, and the arrival that ran the round reports the round's error (sync then fails its step). Read from the code, not built.

Tests: `LocalPeer::receive_with` panics on `Error::Corrupt`, so engine tests and the simulator fail at the receive that trips one.

Open: a commit whose examination errs locally could stay pending, marked, out of the round (examined again after an upgrade or restart), so the rest applies and the node keeps serving, the error reported as a node status rather than a failed step. Which engine `Corrupt` sites can a forged commit reach (each should be `BadInput`)?

Also owed (notes/sync-facade.md Pending): one small world per wait reason and waking event asserting `lost_wakes` empty; a box the reading-only budget refused, freed by room alone, has no wake until the next arrival or tick.

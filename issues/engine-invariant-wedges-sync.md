# A broken engine invariant on one commit takes the node down at every retry
> Summary: an engine `Corrupt` while applying a received commit is a local error: the commit stays unreceived (no cursor passes it), node-sync's streams step fails and the node goes down; after a restart the same body is offered again and fails again. Loud and lossless, but one commit tripping any engine bug (or a forged one, if any hostile input can reach a `Corrupt`) stops the node for good until the code is fixed.
> Priority: normal
> Tags: engine, sync, security

What happens (core/sync/src/streams/pull.rs `take_body`; core/engine/src/sync/bodies.rs `open_entry_once` passes a local-class ingest error up, never `Opened::Bad`): the step fails at the next settle; `streams::an_owed_body_settles_only_once_taken_under_its_sync_id_spec_sync_streams_4` shows the restart refetch. Right for a store failure (transient). For a logic invariant it repeats forever.

Tests: `LocalPeer::receive_with` panics on `Error::Corrupt`, so every engine test and the simulator fail at the receive that trips one (not as a later read difference).

Open: should a node keep serving and taking other commits while one stays unreceivable (the body owed, retried after an upgrade), and report it as a node status rather than a failed step? Which engine `Corrupt` sites can a forged commit reach (each should be `BadInput`)?

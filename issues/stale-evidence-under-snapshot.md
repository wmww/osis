# Staleness evidence lost under a role snapshot
> Summary: Stale reads boxes from held valid `secrets.0` bodies (`Indexes::boxed`); once a role snapshot covers the body that put a box (or a node gets only the snapshot) and a foreign rotation already stripped that box from the state, no held body shows the epoch stale. The removed box records had the same exposure.
> Priority: low
> Tags: security, keys, engine

Found reviewing spar-key-records (776078311). A fix would make the snapshot carry what Stale reads (the boxes its covered bodies put at epochs still current), or judge Stale from the state with foreign rotations' removals not applied (rejected for now: notes/holder-actors.md, the conditional join). Needs a hand world first: a foreign rotation strips a box, a snapshot covers the putting body, a writer then encrypts.

# Staleness evidence lost under a role snapshot
> Summary: Stale reads boxes from held valid `secrets.0` bodies (`Indexes::boxed`); once a role snapshot covers the body that put a box (or a node gets only the snapshot) and a foreign rotation already stripped that box from the state, no held body shows the epoch stale.
> Priority: low
> Tags: security, keys, engine

A fix would make the snapshot carry what Stale reads (the boxes its covered bodies put at epochs still current), or judge Stale from the state with foreign rotations' removals not applied (rejected: notes/holder-actors.md, Stale boxes, box records and carried commits). Needs a hand world first: a foreign rotation strips a box, a snapshot covers the putting body, a writer then encrypts.

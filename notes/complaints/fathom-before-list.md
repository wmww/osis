# fathom-before-list
- `LocalPeer::sync` hands a rotation's lists only through `ingest_with_lists`, which dropped them for a rotation already held (header-only from `take_rotations`), so an engine test of "sibling takes the rotation from a Prove, then syncs" waited on D forever. Fixed in the engine (pairing packages hit the same path); worth knowing when a Waiting test never settles.
- Review 12 rewrote the same rule mid-task; a rebase onto its branch tip was needed before the change made sense.

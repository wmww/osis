# Orphaned and blocked rules count a rotator whose right runs through a keyless grant
> Summary: `rotation::orphaned` (a box holder that may rotate r is a re-sealer) and `blocked_epoch`'s rotator test use `may_rotate`, which counts paths through keyless grants; such a node's rotation or re-seal is invalid (Possession), so an epoch boxed only to it is not judged orphaned and nobody re-seals its holders. Liveness only: no leak.
> Priority: low
> Tags: rotation, keys

- The merger already uses `members::may_rotate_keyed` for this reason; the orphaned rule's "holder that may rotate r" (spec/crypto.md §4, Encrypting under) wants the same reading, stated in the spec.
- `blocked_epoch`: a node whose right runs only through a keyless grant counts as a rotator, so a stale or keyless box blocks it and it waits for another's rotation: stricter than needed, safe.
- Needs a test: a box holder with read directly and write only through a keyless holder actor, the epoch's other holders lacking its secret.

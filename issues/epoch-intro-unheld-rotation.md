# Epoch introducer unknown to a node that never held the rotation body
> Summary: a node that never received an epoch's rotation body (synced after compaction, or the body uncovered and missing) takes the earliest held commit boxing or keying the epoch as its introducer, or none; then `by_departed` and `presumed_boxes` can count an epoch a departed party rotated as covering its departure (no rotation: the departed party keeps reading).
> Tags: security, engine

`Core::epoch_intro` (core/engine/src/apply/keys.rs) is the earliest valid held membership commit boxing an epoch or writing its keyset. A compacting node keeps a dropped part's epochs in its record (`Dropped::intros`), but a node that only ever held the compaction snapshot (or whose body went back to missing, `retention::uncover`) does not know the rotation commit:
- `rotation::uncovered_roles_of` `by_departed`: no intro, or a later grant/re-seal standing in, is "not written by the departed party", so the epoch covers (spec/crypto.md §4 says it must not when the departed party wrote the rotation). Matters when the departed party knows the epoch without holding a box in it: a device acting through a person actor, the person's box later rewritten to name its new keyset.
- `rotation::presumed_boxes`: a later grant standing in as "the commit that set the keyset" is read as boxing no leaver; the spec asks for the delta of the commit that set it (else presume boxed).
- `box_knew` (stale key-actor boxes): a later intro makes a box look written before the epoch.

Options: derive the introducer from the compaction snapshot (the `/keys` keyset register's and the boxes' write dots name their commits, header-held), or treat an epoch whose introducer is not provably held as introduced by anyone (rotate on any departure: one rotation per compaction per admin, which can storm). Unknown with no intro entry is already safe in `presumed_boxes` and `box_knew`, not in `by_departed`.

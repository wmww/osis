# A node holding only a snapshot of a current epoch cannot see its maker depart

> Summary: the maker departure (spec/crypto.md §4 Departure: the author of a current epoch's held rotation commit that no longer holds r) needs that rotation commit (`epoch_intro`); a node that keys the epoch from a `secrets.0`/`keys.0` compaction snapshot only, or after `retention::uncover`, knows no maker, so where the maker's role ran through a keyless holder actor it may encrypt under an epoch the departed maker holds.
> Priority: low
> Tags: security, engine, keys

Shape: the leak `tests_members::maker_lowered_through_a_holder_actor_opens_nothing_new_spec_crypto_4` closes, at a node that joined after the rotation commit's `keys.0` part was compacted away (a snapshot's keyset body records the compactor as author, not the rotator). A node holding the commit rotates, so the leak lasts until its rotation reaches the snapshot-only node: the same reach as the stated ignorant-keyset limit (notes/crypto.md, Holder actors at depth 0, Limits), but here the fact was dropped by retention rather than never received. It needs a writer past its own rules as maker (an honest writer refuses a rotation through a holder actor it cannot prove, `members::authority`), saved by §5.2 (issues/possession-frontier-saved-rotation.md).

Options: retention keeps a current epoch's rotation commit (`keys.0` part) while the epoch is current (as `rotation-keyset-gone-before-its-boxes.md` may want anyway); or close the possession gap so such a rotation is never valid.

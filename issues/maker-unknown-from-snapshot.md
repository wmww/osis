# A node holding only a snapshot of a current epoch cannot see its maker depart

> Summary: the maker departure (spec/crypto.md §4 Departure: the author of a current epoch's held rotation commit that no longer holds r) needs that rotation commit (`epoch_intro`); a node that keys the epoch from a `secrets.0`/`keys.0` compaction snapshot only, or after `retention::uncover`, knows no maker, so where the maker's role ran through a keyless holder actor it may encrypt under an epoch the departed maker holds.
> Priority: low
> Tags: security, engine, keys

Shape: the leak `tests_members::maker_through_keyless_grant_opens_nothing_new_spec_crypto_4` closes, at a node that joined after the rotation commit's `keys.0` part was compacted away (a snapshot's keyset body records the compactor as author, not the rotator). A node holding the commit rotates, so the leak lasts until its rotation reaches the snapshot-only node: the same reach as the stated ignorant-keyset limit (notes/crypto.md, Holder actors at depth 0, Limits), but here the fact was dropped by retention rather than never received. The maker is a writer whose role runs through a keyless grant: its rotation is valid (a keyless grant is a role), though an honest one never makes it (`may_rotate` counts keyed grants only).

A rotation commit's `keys.0` part on a thing keeps only `ROLE_KEEP` past replaced, like any role-class body, so a `keys.0` snapshot may cover it; a current epoch's rotation keeps live boxes, so holders of its `secrets.0` part place that part, but a newcomer may get its keyset from the snapshot alone. Options: keep a current epoch's rotation commit whole while it is current (its maker is a judgment input of the maker departure); or record the maker in the snapshot's keyset (the rotator, not the compactor).

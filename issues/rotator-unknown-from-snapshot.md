# A node holding only a snapshot of a current epoch cannot see its rotator depart
> Summary: The rotator departure (spec/crypto.md §4 Departure: the signer of a current epoch's held rotation commit that no longer holds r) needs that rotation commit (`epoch_intro`); a node that keys the epoch from a `secrets.0`/`keys.0` compaction snapshot only, or after `retention::uncover`, knows no rotator, so where the rotator's role ran through a keyless grant it may encrypt under an epoch the departed rotator holds.
> Priority: low
> Tags: security, engine, keys

The rotator departure closes the leak of a rotator whose role ran through a keyless grant (such a rotator holds the target only by another way: a keyless grant carries nothing, spec/sync-set.md §2); it reopens at a node that joined after the rotation commit's `keys.0` part was compacted away (a snapshot's keyset body records the compactor, not the rotator). It lasts until a node holding the commit rotates and that reaches the snapshot-only node. Only a dishonest rotator reaches it (`may_rotate` counts keyed grants only).

Options: keep a current epoch's rotation commit whole while it is current (its rotator is a judgment input); or record the rotator in the snapshot's keyset.

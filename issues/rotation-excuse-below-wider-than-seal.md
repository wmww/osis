# rotation_holds excuses every blind box to an actor the departed peer reached only from below
> Summary: `Run::excused` (core/engine/src/rotation/tests_property.rs) returns true when departed peer d holds no edge of its own on the blind-boxed holder actor M (`departure_point` is None), whatever the rotator held. The stated limit (spec/crypto.md §4, the "departure from a holder actor M' of M" limit) is narrower: once a keyset of M' superseding the keyset M's epoch boxes reaches the rotator, Seal finds a stale box and leaves M out. A Seal that ignored stale boxes one level down would pass the property.
> Priority: normal
> Tags: security, tests, rotation

Seed 942892035127 is an excused case: actor 2 (admins hostile peer 2, and peer 3 who left forging `Listed`, which writes no keyset) was never re-keyed, and peer 0 reaches it only through a keyless cycle grant, so no knowing keyset of actor 2 existed and actor 1's n1 box to it was not stale at peer 0.

Fix shape: for a blind box to M at k where d reached M only through M's box at k to holder actor M' (at k'), excuse only when the rotator's held set has no epoch of M' made by a rotator holding d's departure from M' and descending past k' (`Run::made` has both); recursively for deeper chains. Today only `co_writer_seals_no_keyset_with_a_stale_box_spec_crypto_4` checks Seal's stale skip.

# An earlier-ordered grant closing a key cycle never reaches a reader
> Summary: an offline sibling's grant of T0 on T1, ordered before Bob's grant of T1 on T0 (which it makes keyless), reaches Bob's node but never Alice's, though she reads T1: her roster of T1 and her key-access judgment diverge from Bob's.
> Priority: normal
> Tags: sync, engine, permissions, tests

Repro: `holding::repro_an_earlier_ordered_grant_reaches_a_later_reader_spec_permissions_5` (ignored). Without Bob's grant of T1 on T0 the sibling's grant does reach Alice. Not diagnosed: whether Alice never fetches the commit, or holds it and her walk leaves it out (parked, unapplied). Found by the retain-rule review: it also hides the case `holding::an_ended_way_found_keyless_drops_its_copy_spec_permissions_3` covers when Alice's grant on T1 comes after the sibling's write.

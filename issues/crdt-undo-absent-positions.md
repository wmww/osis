# Undo leaves values where nothing was before
> Summary: Undoing the first write into a spot that did not exist yet (an optional field inside a nested struct or enum payload, or the first add into a set that was absent) leaves the new value or an empty set behind instead of making the spot absent again.
> Tags: crdt, api

§4.6 restores values, never absence: a register that did not exist is not written (except at an aspect root, which is removed) and a collection emptied by undo stays present. So after undo the read differs from the read before the commit at those spots. `undo_restores_spec_4_6` (tests_ops.rs, `strip_absent`) leaves such spots out of the comparison.

Option (owner's call): undo resets the nearest composite ancestor that was absent before the commit. Cost: that reset also wipes concurrent older writes into the same ancestor.

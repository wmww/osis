# A node test's log order depends on a rotation's random bytes
> Summary: `until::a_write_logged_after_the_rotation_in_its_step_is_not_served_spec_sync_10` asserts an app write placed in the same pass as a rotation is logged after it; which is logged first follows the blobs' random bytes (rotation rng 9 and 11 fail, 10 and 12 pass), so any wire-byte change flips it.
> Priority: normal
> Tags: tests, node

The test's helper `rotate` (core/node/tests/it/until.rs) draws the rotation from a fixed rng; the
pass places the rotation and the write together, and their log positions come out in an order the
bytes decide, not the order they were made. The keyset's `left_out` field (an empty map) changed
the bytes and the draw 9 started failing; it now uses 10, which passes by the same luck. Fix:
make the test order the two by construction (two passes, or a write the pass must place after
the rotation), or decide that a same-pass write may log before the rotation and test the
property the comment states (nothing logged after the rotation is served) on whatever lands after.

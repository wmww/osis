# Single-use direct link redeem sometimes stalls 30 s
> Summary: `runtime::single_use_direct_keeps_key_in_process_spec_permissions_7` (osis it) times out at `bob.redeem(&link)` (`Elapsed`, the 30 s `GUARD`) about 1 run in 100 when 12-14 copies run at once; alone it passes in about 1 s. Same rate on main and sync-pass. It failed one gate.
> Priority: normal
> Tags: tests, osis

Reproduce: run the test binary 14 at a time, 8-12 rounds, count `panicked at core/osis/tests/it/runtime.rs:571`. A redeem that never finishes is a user-visible hang, not only a slow box: the 30 s guard is far above the test's 1 s. `GUARD` equals `SETTLE_MS` (30 s), so a step left to its author that never comes (a settle wait the redeem path depends on) is one suspect; a lost wake under load another.

The sibling `runtime::redeem_direct_writes_at_once_in_process_spec_crypto_7` stalls the same way (`Elapsed` at its `redeem`, runtime.rs:875), so the stall is the direct redeem path's, not one test's. Counted at main 3d6d55ea3, the two tests together, 14 copies of the binary at once: 13 runs of 448 failed (about 3%), so about one tier-1 run in thirty fails on it; it failed a second gate (derived-immutable).

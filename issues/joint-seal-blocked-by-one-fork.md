# A joint box is blocked when any fork it names misses a known departure
> Summary: Seal judges a joint box blocked when any keyset it names is (spec/crypto.md §4, Seal), so a holder actor M whose forks one known departure separates (one fork made before the removal, judged by history or by order) is left out of A until any rotator of M makes M's knowing re-key, though the removed party, lacking the other fork's secret, could open no joint box. With every rotator of M gone for good, M's members read nothing new of A.
> Priority: normal
> Tags: keys, rotation

## Shape
`rotation::members::sealing` cuts at the first role where any keyset Seal gives is `blocked_epoch`. Test `fork_missing_a_known_removal_leaves_holder_out_spec_crypto_4` shows it; Joint.tla does not model `Blocked`, so `J_gone`/`J_stay` describe sealing the build makes only for forks no known departure separates. This waits on no specific device (any rotator of M ends it, as for any uncovered departure from M, spec/permissions.md §3 self-removal), but it is avoidable.

## Direction
Block a joint box for a departure only when every keyset it names misses it, judged per departed party, not per departure edge: x removed from M directly (covered by fork 1) and from N below M (covered only by fork 2's box to N) opens fork 1 through N and fork 2 directly, so a per-edge intersection leaks. Staleness and taint stay "any". Model first: Joint.tla with `Blocked` and a nested holder below M.

# A joint box is blocked when any fork it names misses a known departure
> Summary: Seal judges a joint box blocked when any keyset it names is (spec/crypto.md §4, Seal), so a holder actor M whose forks one known departure separates (one fork made before the removal, judged by history or by order) is left out of A until any rotator of M makes M's knowing re-key, though the removed party, lacking the other fork's secret, could open no joint box. With every rotator of M gone for good, M's members read nothing new of A.
> Priority: normal
> Tags: keys, rotation

## Shape
`rotation::members::sealing` cuts at the first role where any keyset Seal gives is `blocked_epoch`. Test `fork_missing_a_known_removal_leaves_holder_out_spec_crypto_4` shows it; Joint.tla does not model `Blocked`, so `J_gone`/`J_stay` describe sealing the build makes only for forks no known departure separates. This waits on no specific device (any rotator of M ends it, as for any uncovered departure from M, spec/permissions.md §3 self-removal), but it is avoidable.

## Direction
Per departed party leaks (model `JointRule.tla`, `party` fails `NoLeak`): q a member of N and P, both holder actors of M; N removed from M (fork 1 boxes N, fork 2 does not), q removed from P (fork 1 boxes P at its knowing keyset, fork 2 at the old one). Fork 1 misses party N, fork 2 party q, so the rule seals jointly, and q opens fork 1 through N and fork 2 through P. Nothing every node holds tells it q is in N (q may join N later), and two departed parties pooling their secrets break it anyway. Per edge leaks too.

Candidate that passes `NoLeak`, `NoPooledLeak` and `Seals`: block a joint box for departures only when every keyset it names is blocked (some departure each); staleness and taint stay "any". A joint box opens for no one a keyset it names keeps out, so it is as safe as sealing at its least exposed keyset alone; judged from the same per-keyset Blocked as today. Leaves M out where every fork misses some departure (two concurrent removals, one per fork): pooled secrets open that box. Awaiting the coordinator's go.

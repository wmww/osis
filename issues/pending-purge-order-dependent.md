# A purge of a waiting part reads differently by arrival order
> Summary: Since pending-drops, a part a held purge request names while its commit waits counts as never received (no residue), but a node that applied the commit first keeps it value-less (residue). Same commits, different reads; flagged suspect and repaired by a writer's snapshot, as for expiry. Main before it was deterministic (values kept pending until apply). Needs a decision: accept, or strip values from the pending part instead of dropping it.
> Tags: engine, retention, owner-call

Test: `shred::purge_of_a_waiting_part_reads_alike_or_flags_spec_commits_5` (C writes over "old", P purges C's part and resets nothing): orders where C waits when P comes read "old" and flag the aspect; the others read the value-less write (None), as the author does. With a reset in P (spec/commits.md §5 SHOULD) reads agree, but non-value writes (list/text creations, anchors) still differ.

Expiry's same divergence is owner-accepted (the part expired before the node could apply it). For purge it is avoidable: the request is a held commit. Option: keep the pending part with its values stripped (a value-less copy, spec/crdt.md §4.7), joined at apply as `make_valueless` would leave it; costs a schema-aware strip on a delta whose thing may not be resolved yet, and a pending part that no longer matches its header hash.

The random order oracle generates no purge requests, so the `Why::PendingDrop` tolerance it shares with expiry excuses nothing today; adding purges to it would need this settled first.

Also open: `known_purged` reads roles; a concurrent demotion of the purger arriving later turns the judgment false after the part left (the blob and key gone too), so the commit may then wait for it for good.

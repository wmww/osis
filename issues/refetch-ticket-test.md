# Refetch through a ticket's sync ID: no rule test
> Summary: a refetch (`units::refetch`) pulls anew the sync IDs a thing is held by, ticket hints included; only full-size differential seed 65 reaches the ticket arm.
> Priority: low
> Tags: tests, sync

The corner: a reader holds T0 by its ticket's sync ID while no `sync.0` of T0 is held (entered on the ticket's word), and a thing under T0 is released and reached again in that window. With `owned_in` the refetch pulled nothing and the released thing's parked entry never opened. A hand-built test needs that window held open; forgetting T0's keying commit by hand (`forget_commits`) leaves X's record held, so no refetch fires. Build one once the harness can hold a reader before `sync.0` arrives.

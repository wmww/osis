# Two full-size differential seeds fail once edge bytes change
> Summary: `OSIS_FULL=1` `differential::histories_hold_their_closure` seeds 19 (node 4 with sync alone reads thing 0: it reads `v3`, the model does not) and 93 (node 3's sources status counts non-members at quiet) fail after `edge` gained `retain`; both fail the same on main with only an always-false `retain 3: bool` added to `edge`, so they are existing bugs that the new bytes reach (commit IDs move, so do orders), not the change's.
> Priority: normal
> Tags: sync, engine, tests

- Seed 19: the printed script (`differential::holds(19, &script, ..)`) passes on main, fails on main plus the inert field: a read secret of a Keyed thing held where the role commits give sync alone; why_role shows lost access "not due: no secrets of it held". Script ops: `Revoke(2, 0, Node(0))`, `Lower(3, 4, Node(2), Syncs)`, crashes and partitions. Shrink with `OSIS_SYNC_SHRINK=1`.
- Seed 93: `sources status counts that are no member at quiet` for node 3, 7 sync IDs on one connection.
- The differential was 100/100 on main only for main's bytes: every wire change resamples its worlds.

# An expiring diff loses the fields it did not rewrite
> Summary: The structural diff (spec/crdt.md §9) writes only the fields that changed, so a new write with `expires` leaves unchanged fields carried by the previous delta; when that delta expires first (§4.7), those fields go and the struct reads with fields missing. The heartbeat's `/seen` then fails its typed read (`missing field 1`), which aborts the whole sync pass: the node uploads nothing more.
> Tags: crdt, node, sync, tests

- Seen in the simulator: `osis_sim::replay("revocation_bob", 28)` (also seeds 30 and 31, `revocation_carol` 24; regression test `revocation_bob_seed_28`): after the one-day gaps the node's `/seen` reads `{0: ts}` (field 1 `stranded` gone with the expired earlier heartbeat), every pass logs `sync: value: at (root): missing field 1` (`heartbeat_commit`'s `get_typed(&me, &ct::SEEN)?`) and a must-hold body never reaches the server.
- Fixes: the heartbeat writes `/seen` with `replace` (whole value); generally, a write with an expiry diffs against S restricted to the writes that outlive it (or is a replace), which spec/crdt.md §9 could state; and the sync pass should not abort on one typed-read failure.

# The product's per-member standing memo coming due is untested, and may be unobservable
> Summary: osis-sync's `NodeHolds::standing_due` (the engine memo that tells Opens a followed member's J moved) can return nothing and every osis-sync test passes; every J move a world test can make either also moves the node's credentials of S (so the held-records loop judges the member) or leaves the member admissible, so either a world case that isolates it is still to be found, or the memo is redundant.
> Priority: normal
> Tags: tests, sync

Plant (`tools/mutate.py`, whole `-p osis-sync --test it`): `core/sync/src/opens/holds.rs` `self.fx.standing.due()` -> `Vec::<(RecordId, SyncId)>::new()`: none fail.

Opens' own rule is covered: planting `ctx.holds.standing_due()` -> empty, or `self.judge(ctx, r, s, moved)` -> an unfollow, in `Opens::tick` fails six `opens::` `Pair` tests (`standing_is_followed_per_record_across_connections_*`, `a_removal_held_here_closes_a_credential_open_at_once_*`, `a_j_open_closes_when_its_peer_stops_counting_*`, `a_departure_alone_moves_what_read_the_member_*`, `a_departed_store_granted_again_closes_at_its_until_*`, `a_standing_move_costs_the_same_at_n_and_10n_*`). They run on the test `Table`, whose `judge_as` moves J alone; the product's J and credentials come from one engine.

What a world test reaches (node 2 away and back once, then away; node 1 cut off from node 0 where noted):
- a removal, a removal after a restart, a device revocation: the rotation moves node 1's credentials of S, and `moved_creds` judges every record holding S in the step (a revoked device is also judged at the take: its record's named actors move);
- a read grant's `until` passing with node 1 cut off: J moves to departed with nothing else, judged by the standing path, but the read secret's epoch still covers every departure node 1 knows of (`Engine::covers_departures` true), so the member stays open and is served as before: no observable difference;
- a sync grant's `until` passing at a store source with node 1 cut off: the member is ended in the step (until at node 1's log end, nothing written after served; a far `until` serves it), but node 1's credentials of S move too (its `due` reports S with a new digest), so the planted memo still passes.

Next: find a J move that is the only change at the judging node and changes what is served (a member opened by J, `Credential::J`, whose peer departs without a roster change of S's credentials), or show none exists and remove the standing memo (the credentials path then covers §6's J changes).

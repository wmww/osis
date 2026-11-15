# A redeemer never sees its join held, so it follows the link forever
> Summary: status tracks only commits authored by the account or node (`Engine::own_commits_now`), and a link's join is L's, so `Status::held(join)` stays false and `inbox/links.rs` never forgets the link: after every redeem, L is kept, K's sync ID followed via the link and the sharer dialed at the redial pace, for good (spec/permissions.md §7: SHOULD discard the seed once the grant is at a source).
> Priority: normal
> Tags: sync, tests

- Seen: in `links::a_redeemer_joins_k_spec_permissions_7`, after `run()` with the join in node 0's roster, `Node::redeeming(&link.k)` is still true. No test checks the link is forgotten (`links::a_joined_redeem_is_followed_past_the_follow_time_until_its_join_is_held_spec_permissions_7` leaves that assert out, pointing here).
- Tried: adding the followed links' L to `own_commits_now`'s authors makes the join held and the link forgotten, and 13 of 17 `links::` tests fail. Two kinds:
  - Tests calling `Node::redeem` again after the join expect `Done`; once forgotten, it starts a new redeem (`Pending`) and would write a second join. `redeem` should answer `Done` when this account already joined (e.g. K's roster lists it alive, or a role on the target), before `link_ended` (a single-use join removes L).
  - Joiner tests (`a_joiner_leaves_k_*`, `a_joiner_stays_*`: "K on the target at node 1", "node 1's account still holds K") fail once the link is unfollowed: the joined account's own sync of K (and of the target's history K's leave reads) seems to ride on the link being followed. Check what keeps K's sync ID in the sync set for a joiner once L is gone (spec/sync-set.md §2).

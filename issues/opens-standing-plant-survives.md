# The away-change opens tests pass with the in-step standing judgement planted out
> Summary: osis-sync `opens::*_serves_nothing_after_it_*` and `a_device_revoked_while_away_is_served_nothing_after_it_*` all pass with `Opens`' per-step judgement of `standing_due` members removed (or replaced by an unfollow), so nothing shows that a member whose peer's proof moved while it was away is judged in the step of the change rather than at the next take.
> Priority: normal
> Tags: tests, sync

Plants (`tools/mutate.py`, `core/sync/src/opens/mod.rs`, filtered to those four tests), each surviving on main's tests too:
- `ctx.holds.standing_due()` -> `Vec::<(RecordId, SyncId)>::new()`
- `self.judge(ctx, r, s, moved)` -> `{ self.unfollow_member(r, s); ctx.holds.unfollow(r, &s) }`

The tests go away and back once first so the first take after first contact (which judges every member) is behind them (notes/test-harnesses.md, Harness footguns), yet the reconnect still ends the member: either another path judges it (the held-records loop after a change of what this node holds, or the take itself), or the tests observe only what any judgement gives. A fix names which rule each test isolates and checks it fails with that rule alone planted out (notes/test-harnesses.md, Oracles and isolation).

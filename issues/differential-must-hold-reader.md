# A cross-published sync.0 a reader of the publisher released: spec rules conflict
> Summary: osis-sync `differential::histories_hold_their_closure_plain` fails at `OSIS_SYNC_START=285299238820` ("must-hold bodies a caught-up reader lacks at quiet"): a thing's `sync.0` write is in its mint admin's sync ID's required set (spec/sync-ids.md §2, cross-published) whether or not a strong reaches it, but a reader that released the thing forgets it whole (spec/commits.md §5), so readers holding the thing elsewhere judge must-hold what the others dropped. Needs a direction call.
> Priority: normal
> Tags: sync, engine

Shrunk script (2 accounts: nodes 0 and 2 are A, node 1 is B; fails 50 of 50 worlds, OSIS_SYNC_START=1000):
```
New(2), Give(2, 0, Holder::Node(1), Reads), NewIn(2, 0), Run, Strong(1, None, 1),
Give(2, 1, Holder::Node(1), Syncs), Strong(1, None, 0), Unstrong(0, Some(0), 1),
```
A mints t0, gives B read; mints t1 under t0 (strong t0 -> t1); B holds t1 from its root; A gives B sync on t1, which makes t1 independent (the keyset commit writes `sync.0` on t1); B holds t0; A drops the strong t0 -> t1.

Cause: `Engine::publisher(t1)` is t0 (nearest thing with a sync ID up t1's record chain, record edge standing), so `body_things` puts the keyset commit under t0's sync ID (spec/sync-judgement.md §2 "cross-published `sync.0` commits"). After the unstrong, A's nodes release t1 and nothing needs it (spec/commits.md §5), so t1's record and commits go; `publisher` then reads nothing (no `sync_recorded`), and the commit is outside t0's sync ID at A. B still holds t1 (its own strong), judges the commit must-hold under t0's sync ID and logs it; caught-up A lacks it. Same reasoning for `created.0`.

Rejected fix (pushed as origin/mizzen-must-hold-reader-attempt, with a 2-node reproducer in its retention.rs): a retention need "a thing is needed by the thing in the node closure whose sync ID publishes its `sync.0`". It fixes the script (0 of 50) but every thing minted under an account and then released keeps its record forever under the account root's sync ID: fails `closure::own_things_are_released_whole_spec_sync_set_3`, `destruction::a_thing_relying_on_a_destroyed_thing_keeps_its_record_spec_commits_5` and four `growth::*returns_storage*` tests (storage attributable to synced groups).

Options for the call:
- Cross-publish only within the sync unit (drop the rule: `sync.0` goes where any part of the thing goes); a holder of a role through the record edge reaches the sync ID by its inbox as a rotation's holder already does (notes/mint-admins.md, Secrets). Check what fails without `body_things`' publisher term.
- A cross-published body of a thing outside S's sync unit is may-hold (kept if it arrives, never fetched or owed). Weaker, and the required set still depends on a record outside S.

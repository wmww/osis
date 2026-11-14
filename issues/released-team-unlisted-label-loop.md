# A released team not listed in a group: co-admins never get the request, then an endless loop
> Summary: A team (`mint_actor`, first admin g, not in g's `group.0`) released by admin c: the request reaches neither co-admin a nor writer b, c deletes the team's entries at the host (its rotation body included) and forgets it, learns it back from a without that body, so c no longer knows the team has secrets of its own: c and a then loop without end (release build too).
> Priority: critical
> Tags: node-sync, lifetimes, keys

Shape: `destruction::a_forgotten_teams_rotation_leaves_no_index_row_spec_commits_5` with the team left out of g's `group.0` (drop the `items` lines), then `net.advance(ROLE_KEEP_MS)` and a few `advance(70_000)`.

What happens (traced with `OSIS_SYNC_TRACE`):
- At `release`, c judges the team destroyed at once and its node-sync, in the same settle, deletes the team's entries under the team's own label at the host and sends `Lost` for it. a and b never apply the `released.0` commit (their status stays `Known`). A team listed in g's `group.0` gets the request everywhere (the test as written).
- At the request's expiry c forgets the team whole (`retention::destroy::forget_released`, `MemoryDrop::Gone`: node-sync deletes the rest at hosts). a still holds the team live and serves its record back. c then holds the team's rotation header with its valid `keys.0` part missing, and the body is gone from the host, so it never arrives.
- Without that body c cannot know the team has secrets of its own (`Indexes::own_keys` and `keyset_parts` are facts of the body). c keeps the team's epochs (`ix.secrets`: its record is held again, `drop_destroyed_secrets`), but derives its deposit seed and label keys from g (`secret_actor`, `labels::deposit_seed`). a uses the team's own seed. Each sees the other's step as having a stale deposit key and writes a new `label.0` step on every pass (about 44 commits per 2000 messages, without end).
- `keys_write_unapplied` now counts a missing valid `keys.0` part from the group up to its secret actor, so c holds back its deposit-only step. The commit storm stops, but a message loop remains: c places an entry under the team's label, a deletes it (a and b are then sent `Refused`), and this repeats every round. No commits, endless traffic.

On main the release build is quiet here, but only by accident: `unindex_commit` left c's `own_keys`, `keyset_parts`, `keysets` and `epoch_intro` rows naming the forgotten rotation, so c kept treating the team as having its own secrets. A debug build panicked in `check_index` instead. Removing those rows (which is correct) exposes the gap.

Cause: upstream of the engine. A release request on a thing that is synced only under its own label never reaches its other holders before the releaser deletes its entries and leaves the label. The forget then assumes the thing is dead everywhere and deletes bodies (the rotation) that live holders still need. Where to look: node-sync's handling of a thing destroyed here (deletes of a destroyed thing's entries, `pass/delete.rs`; `lifetimes.rs`, a label heard out before anything under it is released) and how a destroying request is placed for holders that do not read the group's label.

Questions: should a forgotten thing coming back from a holder make its forgotten commits fetchable again (re-placed by that holder)? Should a thing whose record arrives after its forget be judged destroyed again (the request is gone here)?

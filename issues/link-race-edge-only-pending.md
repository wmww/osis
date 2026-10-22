# A commit's partial copy pends for ever when the whole commit never reaches its things' labels
> Summary: A node that syncs thing K and receives only part of a commit on K (a chain certificate projected to its `/members` deltas, spec/permissions.md §4, or an edge-only inbox blob) waits (`Reason::WaitDeltas`, atomic apply) for the rest, which only the author can place under K's label; if the whole commit never gets there, it pends for ever.
> Tags: node, sync, tests

Seen: `link_race` 1792, 2255, 2898, 3926 (production round 1 sweep). 2898 (a losing redeemer forgot K before its deposit landed, after its `/members`-only copy reached the target's label) is fixed by queuing a non-writer's copies of its own writes in the outbox (notes/sync.md); 1792, 2255, 3926 pass on main since. Tier-2 seed tests in sim/tests/library.rs.

## Technical details
The `/members`-only copy is legitimate: chain certificates go projected to their edge deltas (spec/permissions.md §4). A receiver that syncs K must then get the full commit from K's label, and nothing guarantees it is there. Ways it never arrives:
- the queued deposit dropped after `MAX_INBOX_TRIES` refusals (budget full, rate limit);
- an admin of K refreshed K's deposit seed before the deposit was answered (signature no longer matches);
- `place_certificate_in` deferred for an uncovered epoch and the node lost the label (or restarted: `deferred` is in memory) before the rotation;
- a crash between `Engine::commit` and `carry_out` (the deliveries are not durable);
- disk loss of the author.

Options:
- Author side: place the full commit under the labels of its things before any partial copy elsewhere (copies wait until the full body is present at a server); the crash and disk-loss cases still need the deliveries durable.
- Receiver side: a rule that a part on a synced thing that no reachable entry can supply (author departed, no holder) is treated as never coming (apply the commit without it, as for dropped parts), with a bound so a slow author is not cut off.

# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential on held-model's stub closure (`Rule::BUILT`) at full size: 12 of 100 seeds fail, by class with a shrunk script or probe line each; the largest are reads unlike the reference (an inbox its account stops holding, a promoted thing read through its mint admin) and storms; the gate seed tools/known_failures.txt lists.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 210 s wall). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it. A script replays in a scratch test (`differential::holds(<world seed>, &script, String::new(), false)` under `OSIS_FULL=1`). Probe lines below are each seed's first failure at full size; scripts marked "world 0" also fail there.

| Class | Seeds |
|---|---|
| Reads a thing unlike the reference | 14, 15 |
| Storm past the cap | 6, 56 |
| Entries waiting for a read secret, not parked | 68 |
| Stub, the model Unread (no listing) | 81 |
| Stub, the model None | 45, 86 |
| None, the model Stub | 42 |
| Reads a thing the model does not hold | 34, 46 |
| Must-hold bodies with no entry at quiet | 35 |

## Reads a thing unlike the reference (14, 15)
Both scripts below fail on origin/main as well (checked at c81d99ff7), on their own world and on world 0: not concurrent promotions, which hold now (one sync ID per thing, spec/sync-ids.md §2; `differential::grantees_of_concurrent_promotions_read_on_one_sync_id_*`). Causes not sorted.
- 15 (shrunk): `New(1), Inbox(1, Some(0)), Give(1, 0, Node(2), Reads), Unstrong(1, None, 0), Strong(2, None, 0)`: node 1's account makes thing 0 its inbox, grants node 2 read, drops its own strong; node 2 holds it by a strong and reads nothing of it.
- 14 (shrunk to 14 steps; the shrink ran out of its CPU budget): `New(3), Run, Give(0, 0, Node(2), Reads), NewIn(3, 0), Run, Give(0, 1, Public, Syncs), New(3), Revoke(0, 0, Node(2)), Run, Revoke(3, 0, Public), NewIn(3, 2), Give(3, 1, Node(2), Syncs), Give(3, 0, Node(2), Reads), Strong(2, None, 1)`: thing 1, minted with thing 0 and made independent by the public's grant, is read through thing 0 by a node granted sync on it and read on thing 0 again; node 2 holds nothing of it.

## Other classes (probe lines; scripts from before the stub vertex change, re-shrink before use)
- **A removed reader kept unread a step behind its readers' head** (no seed; seen by hand, on a world of 2 accounts and 4 nodes, `holds_on(0, 2, 4, ..)`): `New(1), Give(1, 0, Node(0), Reads), Strong(0, None, 0), Run, Give(3, 0, Public, Syncs), Revoke(1, 0, Node(0))`: node 0 keeps thing 0 unread at a step 2 deep while its readers' head is 3 deep (seen before and during the removed-node work; not rechecked on that world since). Passes on world 0 at full size. Cause not sorted.
- **Stub, the model Unread** (81): no listing; `New(1), New(1), Give(1, 1, Node(2), Reads), Strong(2, None, 1), Lower(1, 1, Node(2), Syncs)` (world 0).
- **Stub, the model None** (45, 86): 45 `New(0), New(0), Inbox(0, Some(1)), Give(0, 1, Node(2), Reads), New(1), Strong(2, None, 1), Give(1, 2, Public, Reads), Run, Give(1, 2, Node(0), Syncs)`; 86 unshrunk (the public reads by its grant).
- **Reads a thing the model does not hold** (34, 46): 34 `New(0), New(0), Give(0, 1, Node(1), Syncs), Run, Give(0, 0, Node(2), Syncs), Run, NewIn(0, 1), Run, Give(0, 1, Node(1), Writes), Strong(1, None, 1), Run, NewIn(1, 1)` (world 0); 46 unshrunk.
- **Entries waiting for a read secret, not parked** (68): `New(0), Run, Give(3, 0, Node(1), Reads), Strong(1, None, 0), NewIn(0, 0), Run, Revoke(0, 0, Node(1)), Give(0, 1, Node(1), Reads), Run, Strong(1, None, 1)`.
- **Must-hold bodies with no entry at quiet** (35): `New(0), Pair(3), Partition(3, 1), Run, Give(3, 0, Node(1), Writes), Inbox(4, Some(0)), Partition(3, 0), Run` (world 0).
- **Storm past the cap** (6, 56): a run past 15000 deliveries; 6 unshrunk.
- **None, the model Stub** (42): unshrunk.

## Small size
tools/known_failures.txt lists one gate seed against this issue: 527365123461, now "node 1 reads thing 1 unlike the reference" (not shrunk; its old script, two nodes of one account promoting thing 0 at once, holds now).

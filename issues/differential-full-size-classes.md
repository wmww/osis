# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential on held-model's stub closure (`Rule::BUILT`) at full size: 17 of 100 seeds fail, by class with a shrunk script or probe line each; the largest is the sync ID fork (a design question), then a removed reader never holding the public's grant; the gate seed tools/known_failures.txt lists.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 210 s wall). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it. A script replays in a scratch test (`differential::holds(<world seed>, &script, String::new(), false)` under `OSIS_FULL=1`). Probe lines below are each seed's first failure at full size; scripts marked "world 0" also fail there.

| Class | Seeds |
|---|---|
| Sync ID fork | 0, 5, 15, 53, 70 |
| A removed reader never holds the public's grant | 31, 84 |
| Lowered with the public: must-hold bodies a store lacks | 12 |
| Stub, the model Unread (no listing) | 81 |
| Stub, the model None | 45, 86 |
| None, the model Stub | 42 |
| Reads a thing the model does not hold | 34, 46 |
| Entries waiting for a read secret, not parked | 68 |
| Must-hold bodies with no entry at quiet | 35 |
| Storm past the cap | 56 |

## Sync ID fork (design question: Tess)
Two nodes of one account, apart, each make a dependent thing X independent, so each records its own sync ID (spec/sync-ids.md §2: both stand, X synced through the greatest). A grantee told on the lesser side's sync ID S1 holds S1 alone; once its granter syncs X through S2, nobody serves S1 to it. Hand case: `differential::a_grantee_on_a_sync_id_forks_lesser_side_follows_the_greater_*` (ignored). Probe signature: a node reads X unlike the reference, its contexts read plus X's stub (0, 5, 15, 53). 70 (shrunk, its own world only): `New(3), New(0), Run, Give(3, 1, Public, Reads), Give(0, 1, Node(2), Syncs), Strong(2, None, 1)`: one node makes X public while another of its account grants node 2 sync, no run between. Simplest option seen: a node reading X keeps syncing every sync ID of X it owns (as a node keeping X unread already does); unchecked that the grantee then owns S2 (spec/sync-ids.md §4 Owner).

## A removed reader never holds the public's grant (31, 84)
The node's account loses its own role on X while the public holds sync there, and the node ends holding X as a stub where the model keeps it unread by the public's sync: it holds neither the public's grant commit nor a head listing that counts. 31 (shrunk, its own world only): `New(2), Give(2, 0, Node(0), Reads), Give(2, 0, Node(1), Reads), Lossy(Loss { drop: 50, dup: 50, delay: 0, delay_ms: 312 }), Revoke(2, 0, Node(1)), Give(2, 0, Public, Syncs), Strong(0, None, 0), Revoke(2, 0, Node(0))` (without the loss it is `differential::a_removed_reader_keeps_the_publics_sync_secret_*`, which passes): node 0 holds the `sync.0` write placing its head (its removal), so the listing yields to the grants (`Core::public_listed`), and it lacks the public's grant, no sync secret held. 84 (shrunk, world 0): `New(2), New(0), New(1), NewIn(0, 1), Give(0, 1, Node(1), Syncs), Pair(0), Run, Give(4, 1, Public, Syncs), Strong(1, None, 1), Revoke(0, 1, Node(1)), Give(0, 3, Node(1), Reads)`: no listing at all, a sync secret by counted copies. spec/sync-opens.md §6 serves a departed member the public's edge; unchecked whether that service is lost here (under loss in 31, beside a concurrent writer in 84). Cause not sorted.

## Lowered with the public: must-hold bodies a store lacks (12)
12 (shrunk, world 0): `New(1), Give(1, 0, Node(2), Syncs), Give(1, 0, Public, Reads), Strong(2, None, 0), Revoke(1, 0, Node(2)), Lower(1, 0, Public, Syncs)`: "must-hold bodies a caught-up reader lacks at quiet": node 2 lacks every entry of S node 1 holds, the first the role commit writing X's `roles.0` and `secrets.0`. Cause not sorted.

## Other classes (probe lines; scripts from before the stub vertex change, re-shrink before use)
- **Stub, the model Unread** (81): no listing; `New(1), New(1), Give(1, 1, Node(2), Reads), Strong(2, None, 1), Lower(1, 1, Node(2), Syncs)` (world 0).
- **Stub, the model None** (45, 86): 45 `New(0), New(0), Inbox(0, Some(1)), Give(0, 1, Node(2), Reads), New(1), Strong(2, None, 1), Give(1, 2, Public, Reads), Run, Give(1, 2, Node(0), Syncs)`; 86 unshrunk (the public reads by its grant).
- **None, the model Stub** (42): shrunk to 15+ steps (a public dependent, pairing and unpairing); not sorted.
- **Reads a thing the model does not hold** (34, 46): 34 `New(0), New(0), Give(0, 1, Node(1), Syncs), Run, Give(0, 0, Node(2), Syncs), Run, NewIn(0, 1), Run, Give(0, 1, Node(1), Writes), Strong(1, None, 1), Run, NewIn(1, 1)` (world 0); 46 unshrunk.
- **Entries waiting for a read secret, not parked** (68): `New(0), Run, Give(3, 0, Node(1), Reads), Strong(1, None, 0), NewIn(0, 0), Run, Revoke(0, 0, Node(1)), Give(0, 1, Node(1), Reads), Run, Strong(1, None, 1)`.
- **Must-hold bodies with no entry at quiet** (35): `New(0), Pair(3), Partition(3, 1), Run, Give(3, 0, Node(1), Writes), Inbox(4, Some(0)), Partition(3, 0), Run` (world 0).
- **Storm past the cap** (56): `New(2), Give(2, 0, Node(1), Syncs), Run, Give(2, 0, Node(1), Reads), Lower(2, 0, Node(1), Syncs)` on its seed's world only.

## Small size
6 seeds: all hold. tools/known_failures.txt lists one gate seed against this issue: 527365123461, the fork (`New(2), Run, Give(0, 0, Node(1), Syncs), Give(2, 0, Public, Reads), Strong(1, None, 0)`).

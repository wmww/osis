# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential on held-model's stub closure (`Rule::BUILT`) at full size: 21 of 100 seeds fail, by class with a shrunk script or probe line each; the largest class is the public's role known only by the heads listing it (fix blocked by a redeemer that never holds the public's grant), the sync ID fork is a design question; the gate seed tools/known_failures.txt lists.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 200 s wall). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it. A script replays in a scratch test (`differential::played_on(0, 3, 4, &script, String::new(), false)` then `history::check`, full size). Probe lines below are each seed's first failure at full size; scripts marked "world 0" also fail there.

## The public's role known only by the heads listing it (2, 14, 31, 48, 70, 84, 85)
Every one: the node holds a sync secret of X alone, "the public: None by its grant, listed at the heads Sync", and holds X as a stub or not at all where the model keeps it unread or reads it. Hand case `differential::a_removed_reader_keeps_the_publics_sync_secret_*` (ignored); 31 `New(2), Give(2, 0, Node(0), Reads), Give(2, 0, Node(1), Reads), Run, Lossy(..), Revoke(2, 0, Node(1)), Give(2, 0, Public, Syncs), Strong(0, None, 0), Revoke(2, 0, Node(0))`; 85 `New(2), Give(2, 0, Public, Syncs), Give(2, 0, Node(0), Reads), Strong(3, None, 0)` (world 0, node 0).
- Cause: a unit carries X (`units::edge_carries`) by the public's role only as its grant held shows it; the heads listing the public (spec/sync.md §3 Holders by copies) count nowhere but a node already keeping X unread, so a node that knows the public's role by its box alone enters nothing.
- Counting the listing as the public's role everywhere (carriage, `Core::enter` giving read where the listing does, the public entry shown and tested in `credentials_of`) passes the hand case, but `differential::a_public_thing_redeemed_is_read_until_the_public_goes_*` and three redeemer siblings then fail: a locator's redeemer of a public thing enters X read by the listing before it holds the public's grant commit, reads the value, and never ingests that commit (its roster lacks the public; it reads on after the public's removal). Not sorted: which source should serve it the public's edge once it reads by read secrets rather than by the public entry (`opens::holds`).

## Lowered with the public (12; hand cases `differential::a_node_lowered_with_the_public_*`, three, ignored)
12 (shrunk): `New(1), Give(1, 0, Node(2), Syncs), Run, Give(1, 0, Public, Reads), Strong(2, None, 0), Revoke(1, 0, Node(2)), Lower(1, 0, Public, Syncs)`: "must-hold bodies a caught-up reader lacks at quiet" (the reader never holds the maker's `sync.0` commits). The hand cases: the lowered node keeps the thing unread with no store path (no step registered with it), its readers' head 4 deep. Cause not sorted.

## Sync ID fork (design question: Tess)
Two nodes of one account, apart, each make a dependent thing X independent, so each records its own sync ID (spec/sync-ids.md §2: both stand, X synced through the greatest). A grantee told on the lesser side's sync ID S1 holds S1 alone; once its granter syncs X through S2, nobody serves S1 to it. Hand case: `differential::a_grantee_on_a_sync_id_forks_lesser_side_follows_the_greater_*` (ignored). Seeds 0, 5 and 53 (node reads unlike the reference; contexts read plus the thing's stub) and the gate seed. Simplest option seen: a node reading X keeps syncing every sync ID of X it owns (as a node keeping X unread already does); unchecked that the grantee then owns S2 (spec/sync-ids.md §4 Owner).

## Other classes (probe lines; scripts from before the stub vertex change, re-shrink before use)
- **Reads unlike the reference** (15): node 2 reads thing 0 unlike the reference, contexts read plus its stub (the fork's signature; not shrunk again). Its earlier script: `New(1), Inbox(1, Some(0)), Give(1, 0, Node(2), Reads), Unstrong(1, None, 0), Strong(2, None, 0)`.
- **Stub, the model Unread** (81): no listing; `New(1), New(1), Give(1, 1, Node(2), Reads), Strong(2, None, 1), Lower(1, 1, Node(2), Syncs)` (world 0).
- **Stub, the model None** (45, 86): 45 `New(0), New(0), Inbox(0, Some(1)), Give(0, 1, Node(2), Reads), New(1), Strong(2, None, 1), Give(1, 2, Public, Reads), Run, Give(1, 2, Node(0), Syncs)`; 86 unshrunk (the public reads by its grant).
- **None, the model Stub** (42): shrunk to 15+ steps (a public dependent, pairing and unpairing); not sorted.
- **Reads a thing the model does not hold** (34, 46): 34 `New(0), New(0), Give(0, 1, Node(1), Syncs), Run, Give(0, 0, Node(2), Syncs), Run, NewIn(0, 1), Run, Give(0, 1, Node(1), Writes), Strong(1, None, 1), Run, NewIn(1, 1)` (world 0); 46 unshrunk.
- **Entries waiting for a read secret, not parked** (68): `New(0), Run, Give(3, 0, Node(1), Reads), Strong(1, None, 0), NewIn(0, 0), Run, Revoke(0, 0, Node(1)), Give(0, 1, Node(1), Reads), Run, Strong(1, None, 1)`.
- **Must-hold bodies with no entry at quiet** (35): `New(0), Pair(3), Partition(3, 1), Run, Give(3, 0, Node(1), Writes), Inbox(4, Some(0)), Partition(3, 0), Run` (world 0).
- **Storm past the cap** (56): `New(2), Give(2, 0, Node(1), Syncs), Run, Give(2, 0, Node(1), Reads), Lower(2, 0, Node(1), Syncs)` on its seed's world only.

## Small size
6 seeds: all hold. tools/known_failures.txt lists one gate seed against this issue: 527365123461, the fork (`New(2), Run, Give(0, 0, Node(1), Syncs), Give(2, 0, Public, Reads), Strong(1, None, 0)`).

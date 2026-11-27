# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential on held-model's stub closure (`Rule::BUILT`) at full size: 70 of 100 seeds fail, 46 of them on R3b's held-signal-as-Read bug; the rest by class with what is known of each cause, and the gate seeds tools/known_failures.txt lists. Each class to become a hand-written test.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes change: work from scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 275 s wall). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it; a script replays in a scratch test (`differential::holds_on(0, 3, 4, &script, String::new(), false)`, full size).

## Full size (100 seeds, 4 nodes of 3 accounts, 60 steps)
By first panic:
- **A held grant signal holds S as Read** (46: "Read, the model Stub" 4 6 8 10 11 13 16 20 22 24 27 29 40 41 43 46 49 51 54 55 59 64 68 72 77 78 79 80 91 94; "Read, the model Unread" 2 12 17 19 21 25 26 30 31 32 42 45 61 81 85 89 99). `thing_sync_now`'s followed-link branch gives `ThingSync::Read` for a thing a held signal follows, whatever the node holds of it, and `thing_holdings` gives `Holding::Stub` only where a read secret is held: a sync-only grantee holds S as Read, and so does a holder removed after its grant was signalled (seed 10: `Give(2, 0, Holder::Node(0), Syncs)`, `Revoke(2, 0, Holder::Node(0))`: role none, no secret, sync set Read). R3b fixes it; the osis-sync tests it blocks are ignored `stub rewrite: a signalled sync-only holder holds S as Read (R3b)`.
- **Entries waiting for a read secret, not parked** (7 23 38 50 57 82 84 86): `World::parks`' check; unshrunk.
- **Reads unlike the reference** (0 15 53 66 96): unshrunk.
- **A holder named in a carried thing's roster held as a stub** (70 73; "Stub, the model None"): spec/data-model.md §8 What counts makes `roles.0`'s holders references (weaks), so a unit carrying X holds the stub of every holder in X's roster that its keys open; the model has no such reference (a grant is the target's data, not a reference to its holder). Spec against the model: notes/stub-rewrite.md, Open for Tess.
- **A paired node never enters its account** (90 97): in `world_of`'s own setup (`World::pair`, then a run): node 3 paired by node 0 holds no role on account 0 at quiet. Unshrunk; the pairing check (`World::pairs_entered`) found it.
- One each, unshrunk: the walk read behind the held set (5); a storm past 15,000 deliveries (62); the `secrets` index rebuilt from the commit records differs from the live one (52); sync set None, the model Unread (65); a node reads a thing the model does not hold (34); must-hold bodies with no entry at quiet (35).

## Small size
6 seeds: 5 hold; seed 2 is the held-signal class. tools/known_failures.txt lists two gate seeds against this issue: 277009481497 (the held-signal class) and 527365123461 ("node 1 reads thing 0 unlike the reference", unshrunk).

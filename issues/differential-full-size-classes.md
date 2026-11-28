# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 1 of 100 seeds fails (45, a delivery storm); at small size: a stub the model holds that the node does not, a thing the model keeps unread that the node does not hold, entries waiting for a read secret, not parked, a live secrets index unlike the store opened afresh.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in two `tools/heavy` holds of 50 (`OSIS_SYNC_START=0`/`50`, `OSIS_SYNC_SEEDS=50`; about 170 s wall each at load 100). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it, in a hold, from a copied test binary (edits to the tree then do not rebuild under it); the seed timeout counts per candidate, so a full-size shrink needs no raised `OSIS_SEED_TIMEOUT_SECS`. A script replays in a scratch test (`differential::holds_on(0, 3, 4, &script, String::new(), false)`: full size is 3 accounts over 4 nodes). Each seed below fails on main.

| Class | Seeds (full size) |
|---|---|
| A stub the model holds that the node does not | none at full size; small size `OSIS_SYNC_START=62853083561` |
| A thing the model keeps unread that the node does not hold | none at full size; small size `OSIS_SYNC_START=109415603779` |
| A delivery storm | 45 ("storm: past the cap of 15000 deliveries in one run") |
| Entries waiting for a read secret, not parked | none at full size; small size `OSIS_SYNC_START=940149075780` |
| A node's live secrets index differs from its store opened afresh (`check_index`: `Table("secrets", ..)`) | small size `OSIS_SYNC_START=2592891347` |

Shrink from the seed with the property's shrinker: a replayed script does not shrink.

## A stub the model holds that the node does not
Small size `OSIS_SYNC_START=62853083561` ("node 0's sync set holds thing 0 as None, the model Some(Stub)"). Not diagnosed.

## A thing the model keeps unread that the node does not hold
Small size `OSIS_SYNC_START=109415603779` ("node 0's sync set holds thing 0 as None, the model Some(Unread)"), failing on main before the record weaks reached the model too. Not diagnosed.

## A delivery storm (45)
Not diagnosed, not shrunk. On a tree a few commits older the same seed failed past this point as a stub the node holds that the model does not (thing 2, read by the public, a stub at node 2): if that comes back, check first whether the stub comes from a weak in a current value the model lacks (a card, an inbox setting: `history::Model::of` gives held-model records' weaks alone).

## Entries waiting for a read secret, not parked
Small size `OSIS_SYNC_START=940149075780` ("node 1: entries waiting for a read secret, not parked"). Not shrunk.

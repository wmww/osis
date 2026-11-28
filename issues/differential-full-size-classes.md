# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 2 of 100 seeds fail (15, 45); classes: a reader reading unlike the reference (15, shrunk to 20 steps), a delivery storm (45); a stub the model holds that the node does not, a thing the model keeps unread that the node does not hold, entries waiting for a read secret, not parked (small size).
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in two `tools/heavy` holds of 50 (`OSIS_SYNC_START=0`/`50`, `OSIS_SYNC_SEEDS=50`; about 170 s wall each at load 100). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it, in a hold, from a copied test binary (edits to the tree then do not rebuild under it); the seed timeout counts per candidate, so a full-size shrink needs no raised `OSIS_SEED_TIMEOUT_SECS`. A script replays in a scratch test (`differential::holds_on(0, 3, 4, &script, String::new(), false)`: full size is 3 accounts over 4 nodes). Each seed below fails on main.

| Class | Seeds (full size) |
|---|---|
| A stub the model holds that the node does not | none at full size; small size `OSIS_SYNC_START=62853083561` |
| A thing the model keeps unread that the node does not hold | none at full size; small size `OSIS_SYNC_START=109415603779` |
| A reader reads unlike the reference | 15 ("node 2 reads thing 0 unlike the reference") |
| A delivery storm | 45 ("storm: past the cap of 15000 deliveries in one run") |
| Entries waiting for a read secret, not parked | none at full size; small size `OSIS_SYNC_START=940149075780` |

Shrink from the seed with the property's shrinker: a replayed script does not shrink.

## A stub the model holds that the node does not
Small size `OSIS_SYNC_START=62853083561` ("node 0's sync set holds thing 0 as None, the model Some(Stub)"). Not diagnosed.

## A thing the model keeps unread that the node does not hold
Small size `OSIS_SYNC_START=109415603779` ("node 0's sync set holds thing 0 as None, the model Some(Unread)"), failing on main before the record weaks reached the model too. Not diagnosed.

## A reader reads unlike the reference (15)
Not diagnosed. Shrunk from seed 15 (60 to 20 steps, the candidate budget spent; the script passes in seed 0's world): node 1 mints thing 0, grants node 2's account read, writes v8 and unstrongs thing 0; node 2 strongs thing 0 only at the end, with no `Run` between, and reads nothing where the reference reads v8 (node 2 holds thing 0's role entries, no content). Look at whether node 1's release waits for node 2's account (spec/sync-set.md §3 To be waited for) and what the end check counts as lost there.
```
New(1), New(2), Write(2, 1), Write(2, 1), Pair(2), Give(1, 0, Holder::Node(2), Reads), Write(4, 0), Write(1, 0), Run, Give(2, 1, Holder::Public, Reads), Give(4, 1, Holder::Node(0), Syncs), Run, Write(2, 1), Write(1, 0), Strong(0, None, 1), Unstrong(1, None, 0), New(2), Disk(4, 1, Fail), Give(2, 1, Holder::Thing(2), Syncs), Strong(2, None, 0)
```

## A delivery storm (45)
Not diagnosed, not shrunk. On a tree a few commits older the same seed failed past this point as a stub the node holds that the model does not (thing 2, read by the public, a stub at node 2): if that comes back, check first whether the stub comes from a weak in a current value the model lacks (a card, an inbox setting: `history::Model::of` gives held-model records' weaks alone).

## Entries waiting for a read secret, not parked
Small size `OSIS_SYNC_START=940149075780` ("node 1: entries waiting for a read secret, not parked"). Not shrunk.

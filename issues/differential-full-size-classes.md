# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 2 of 100 seeds fail (15, 45); classes: a reader reading unlike the reference (15), a store left at an older step (45); a stub the model holds that the node does not, a thing the model keeps unread that the node does not hold (small size); entries waiting for a read secret, not parked (small size).
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in two `tools/heavy` holds of 50 (`OSIS_SYNC_START=0`/`50`, `OSIS_SYNC_SEEDS=50`; about 170 s wall each at load 100). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it, in a hold, from a copied test binary (edits to the tree then do not rebuild under it); the seed timeout counts per candidate, so a full-size shrink needs no raised `OSIS_SEED_TIMEOUT_SECS`. A script replays in a scratch test (`differential::holds_on(0, 3, 4, &script, String::new(), false)`: full size is 3 accounts over 4 nodes). Each seed below fails on main.

| Class | Seeds (full size) |
|---|---|
| A stub the model holds that the node does not | none at full size; small size `OSIS_SYNC_START=62853083561` |
| A thing the model keeps unread that the node does not hold | none at full size; small size `OSIS_SYNC_START=109415603779` |
| A reader reads unlike the reference | 15 ("node 2 reads thing 0 unlike the reference") |
| A store kept unread at an older step than its readers' head | 45 |
| Entries waiting for a read secret, not parked | none at full size; small size `OSIS_SYNC_START=940149075780` |

None is shrunk on the current tree. Shrink from the seed with the property's shrinker: a replayed script does not shrink.

## A stub the model holds that the node does not
Small size `OSIS_SYNC_START=62853083561` ("node 0's sync set holds thing 0 as None, the model Some(Stub)"). Not diagnosed.

## A thing the model keeps unread that the node does not hold
Small size `OSIS_SYNC_START=109415603779` ("node 0's sync set holds thing 0 as None, the model Some(Unread)"), failing on main before the record weaks reached the model too. Not diagnosed.

## A reader reads unlike the reference (15)
Not diagnosed. An earlier shrink (a disk failure on a node paired with the reader) passes on the current tree: shrink again.

## A store at an older step (45)
Node 1 keeps thing 0 unread at a step 3 deep while its readers' head is 5 deep, holding sync[4] by a claim (`node 1 keeps thing 0 unread at step .. (3 deep), its readers' head is 5 deep`). No reader registers the later steps there. The steps past node 1's key are registered only by a member at a store source (spec/sync-ids.md §6 Walk), and node 1 opens S only at a head it holds a key or claim for. A store asks no Head (spec/sync-opens.md §5): path marks tell only a tester that would.

## Entries waiting for a read secret, not parked
Small size `OSIS_SYNC_START=940149075780` ("node 1: entries waiting for a read secret, not parked"). Not shrunk.

# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 10 of 100 seeds fail, by class with a shrunk script and diagnosis where one was made; the largest is holding less than the model (probe lines only, not shrunk); the gate seed tools/known_failures.txt lists.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in two `tools/heavy` holds of 50 (`OSIS_SYNC_START=0`/`50`, `OSIS_SYNC_SEEDS=50`; about 140 s wall each, while one hold of 100 on a loaded box took 590 s of its 598 s cap). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it (a seed's shrink takes about 10 minutes in a hold). A script replays in a scratch test (`differential::holds(<world seed>, &script, String::new(), false)` under `OSIS_FULL=1`). Probe lines below are each seed's first failure at full size; scripts marked "world 0" also fail there.

| Class | Seeds |
|---|---|
| Holds less than the model: reads unlike the reference, or None or a stub where it keeps unread or holds a stub | 29, 41, 45, 68, 86, 99 |
| Reads a thing the model does not hold | 34 |
| Must-hold bodies with no entry at quiet | 35 |
| Entries waiting for a read secret, not parked | 82 |

## Holds less than the model (not shrunk)
Probe lines: 29 and 86 "node 2 (0) reads thing 0 unlike the reference"; 99 "node 1's sync set holds thing 0 as Some(Stub), the model Some(Unread)"; 45 and 68 "... as None, the model Some(Unread)"; 41 "... as None, the model Some(Stub)". Shrink each first: some may be the oracle counting a grant a node cannot learn by another route than the chains `entry::Know` covers.

## Reads a thing the model does not hold (34 shrunk, not diagnosed)
`New(0), New(0), Give(0, 1, Node(1), Syncs), Run, Unpair(0, 3), Run, NewIn(0, 1), Run, Give(0, 1, Node(1), Writes), Strong(1, None, 1), Run, NewIn(1, 1)` (world 0): node 0 reads thing 3 (minted by node 1 in thing 1, whose admin is node 0's account), which the model does not hold. The model's strongs lack thing 1's strong to thing 3 and the reference for node 0's account reads no value of it, so the reference judges node 1's minting commit apart from node 0's engine: start at the reference.

## Other classes
Not shrunk: one seed each, probe lines in a full run's log.
- Default size too: `OSIS_SYNC_START=2 OSIS_SYNC_SEEDS=1` (no `OSIS_FULL`) fails "node 0's sync set holds thing 0 as Some(Stub), the model Some(Unread)", at 9f959ed3b with or without the two fixes after it; not shrunk.

## Small size
tools/known_failures.txt lists one gate seed against this issue: 527365123461, "node 1 reads thing 1 unlike the reference" (not shrunk).

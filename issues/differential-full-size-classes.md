# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 14 of 100 seeds fail, by class with a shrunk script and diagnosis where one was made; the largest is a node the model gives a holder's grants it cannot learn (a sync-only or untold chain holder, Tess's open question in notes/stub-rewrite.md), then a released thing's grant the model counts kept; the gate seed tools/known_failures.txt lists.
> Priority: normal
> Tags: sync, engine, tests, tess-call

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 590 s wall on a loaded box, against the hold's 598 s cap: split the range across two holds next time). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it (a seed's shrink takes about 10 minutes in a hold). A script replays in a scratch test (`differential::holds(<world seed>, &script, String::new(), false)` under `OSIS_FULL=1`). Probe lines below are each seed's first failure at full size; scripts marked "world 0" also fail there.

| Class | Seeds |
|---|---|
| Holds nothing (or a stub) where the model reads or keeps a thing: a holder's grant it cannot learn | 10, 23, 28, 29, 81, 86, 99 |
| Reads the thing, holds none of its content | 15, 68 |
| Reads a thing the model does not hold | 34 |
| None, the model Stub | 41 |
| None, the model Unread | 45 |
| Must-hold bodies with no entry at quiet | 35 |
| Entries waiting for a read secret, not parked | 82 |

## A holder's grant the node cannot learn (28, 81 shrunk; 10, 23, 29, 86 by their probe lines)
- 28: `New(1), New(2), Give(2, 1, Node(1), Writes), Give(2, 1, Node(0), Reads), Strong(1, Some(0), 1), Run, Give(1, 0, Node(0), Syncs), Give(1, 0, Thing(1), Reads), Strong(0, None, 0)` (world 0). Node 0 reads thing 1 and keeps thing 0 unread by its own sync grant; thing 1 holds read on thing 0, so the model has node 0 read thing 0. Node 0 cannot open thing 0's roster (it holds thing 0's sync secret alone), the grant to thing 1 tells nobody (a plain thing names no inbox), and no unit node 0 reads carries thing 0 through thing 1: nothing names thing 1 to node 0 as a holder it reaches thing 0 through.
- 81: `New(1), New(1), Give(1, 1, Node(2), Syncs), Give(1, 0, Node(2), Syncs), Strong(2, None, 0), Give(1, 0, Thing(1), Syncs), Revoke(1, 0, Node(2)), Strong(2, None, 1)` (world 0): the same at sync (node 2 keeps thing 1 unread; thing 1 holds sync on thing 0). Its script is the hand test, with an assertion of how node 2 holds thing 0, once decided.
- held-model abstracts the gap away ("every node follows the stubs it holds, so the grants it knows are the world's current ones"). Options and the sealing decision: notes/stub-rewrite.md (Open, Tess).

## Reads the thing, holds none of its content (15 shrunk)
`New(1), Give(1, 0, Public, Reads), Run, Give(1, 0, Node(2), Syncs), Unstrong(1, None, 0), Strong(2, None, 0)` (world 0; its first failure there is a bare stub where the model gives node 2 the public's read). Node 1's account releases thing 0 everywhere before node 2 holds it, so no node syncs thing 0 and node 2 holds a bare stub (by its grant signal): the engine is right. The oracle (`lost_writes`) keeps the public's grant: the grant's event counts as surely received by node 2 (it got the commit while holding nothing of thing 0, so kept none) and node 2's account holds thing 0 at the end (the stub), so `shared` holds. Fix in the oracle: count a node as having kept a write only where its account held the thing when the write froze, from the history. 68 has the same probe shape (role right, content held false), not shrunk.

## Reads a thing the model does not hold (34 shrunk, not diagnosed)
`New(0), New(0), Give(0, 1, Node(1), Syncs), Run, Unpair(0, 3), Run, NewIn(0, 1), Run, Give(0, 1, Node(1), Writes), Strong(1, None, 1), Run, NewIn(1, 1)` (world 0): node 0 reads thing 3 (minted by node 1 in thing 1, whose admin is node 0's account), which the model does not hold. The model's strongs lack thing 1's strong to thing 3 and the reference for node 0's account reads no value of it, so the reference judges node 1's minting commit apart from node 0's engine: start at the reference.

## Other classes
Not shrunk: one seed each, probe lines in a full run's log.

## Small size
tools/known_failures.txt lists one gate seed against this issue: 527365123461, "node 1 reads thing 1 unlike the reference" (not shrunk).

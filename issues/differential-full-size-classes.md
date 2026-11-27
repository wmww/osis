# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 20 of 100 seeds fail, by class with a shrunk script and diagnosis where one was made; the largest are reads unlike the reference (an inbox its account releases), a reference twin's index unlike its rebuild (pending boxes' history), reads the model does not hold, and a sync-only chain kept unread; the gate seed tools/known_failures.txt lists.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 210 s wall). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it. A script replays in a scratch test (`differential::holds(<world seed>, &script, String::new(), false)` under `OSIS_FULL=1`). Probe lines below are each seed's first failure at full size; scripts marked "world 0" also fail there.

| Class | Seeds |
|---|---|
| Reads a thing unlike the reference | 10, 15, 28, 29, 65, 68 |
| A reference twin's index unlike its rebuild (`secrets`) | 23, 84, 86, 89 |
| Reads a thing the model does not hold | 34, 46, 58 |
| Stub, the model Unread | 81, 99 |
| None, the model Stub | 41 |
| Kept unread a step behind its readers' head | 45 |
| Must-hold bodies a caught-up reader lacks | 47 |
| Must-hold bodies with no entry at quiet | 35 |
| Certificate blobs kept missing (effects read) | 82 |

## Reads a thing unlike the reference (15 shrunk; the others not)
`New(1), Inbox(1, Some(0)), Give(1, 0, Node(2), Reads), Unstrong(1, None, 0), Strong(2, None, 0)` (world 0; also `holds_on(0, 3, 4, ..)`; passes without the `Inbox` or with a `Run` before the `Unstrong`). Node 1 releases thing 0 with its grant to node 2 received nowhere, but keeps the grant commit as evidence: its account's `keys.0` names thing 0 as its inbox (spec/commits.md §5 What a held thing needs). `lost_writes` counts a commit any node holds as not lost, so the model gives node 2 read; no node syncs thing 0's sync ID, so node 2 holds a stub with the admin role alone. An oracle question: options (a) `lost_writes` counts a commit held only by nodes not syncing its thing as lost; (b) the spec has a node keep its account's inbox synced (an account's inbox is in its node closure).

## A reference twin's index unlike its rebuild (23 shrunk, fails on world 23 only)
`New(3), NewIn(3, 0), Give(3, 0, Node(1), Syncs), Run, Revoke(3, 0, Node(1)), Run, Give(3, 1, Public, Syncs), Give(0, 0, Public, Syncs)` on `holds(23, ..)` under `OSIS_FULL=1`: the stranger account's twin (`reference`) fails `check_index` at its drop: a derived sync epoch of thing 1 lists a superseded epoch live but not rebuilt. The divergence comes with a role commit handed while `Pending(Drift)`: `read_pending_boxes` opens its history box (`SecretsRead::Pending` clears nothing and sets the epoch's `supersedes`), while a rebuild re-observes the `secrets.0` states (`SecretsRead::State` clears every epoch's history) and reads no pending box after. Live has the same order dependence (a state ingest after a pending read clears it). Options: (a) a pending (unchecked) box sets secrets only, no names or supersedes; (b) every state ingest of an actor, and the rebuild, read the held pending commits' boxes on it again.

## Stub, the model Unread (81 shrunk)
`New(1), New(1), Give(1, 1, Node(2), Syncs), Give(1, 0, Node(2), Syncs), Strong(2, None, 0), Give(1, 0, Thing(1), Syncs), Revoke(1, 0, Node(2)), Strong(2, None, 1)` (world 0). Node 2 keeps thing 1 unread (sync), thing 1 holds sync on thing 0, node 2 strongs thing 0: the model keeps thing 0 unread through the chain; the engine holds a stub, no sync secret of thing 0. An entry is sealed to its holder's read KEM key (spec/sync-ids.md §3 Entry), which a node syncing thing 1 alone lacks, so no entry gives it thing 0's sync secret. A spec question: options (a) a sync holder's entry also sealed to its sync keyset's KEM key (its keyset carries one, spec/crypto.md §3 Published KEM keys); (b) the model and spec/sync-set.md §2 count a chain holder only where the node reads it.

## Reads a thing the model does not hold (34 shrunk, not diagnosed)
`New(0), New(0), Give(0, 1, Node(1), Syncs), Run, Unpair(0, 3), Run, NewIn(0, 1), Run, Give(0, 1, Node(1), Writes), Strong(1, None, 1), Run, NewIn(1, 1)` (world 0): node 0 reads thing 3 (minted by node 1 with thing 1 as admin), which the model does not hold.

## Other classes
Not shrunk: one seed each, probe lines in a full run's log.

## Small size
tools/known_failures.txt lists one gate seed against this issue: 527365123461, now "node 1 reads thing 1 unlike the reference" (not shrunk; its old script, two nodes of one account promoting thing 0 at once, holds now).

# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 7 of 100 seeds fail (15, 29, 35, 45, 68, 86, 99); classes: a heard head goes stale (29), a stub granted read tests nothing (86), a public-synced thing reached through a dependent holds nothing (68), a store left at an older step (45), must-hold bodies with no entry at quiet (35), 15 and 99 not shrunk anew; entries waiting for a read secret, not parked (small size).
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in two `tools/heavy` holds of 50 (`OSIS_SYNC_START=0`/`50`, `OSIS_SYNC_SEEDS=50`; about 170 s wall each at load 100). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it, in a hold, from a copied test binary (edits to the tree then do not rebuild under it), with `OSIS_SEED_TIMEOUT_SECS=5400` (a full-size shrink passes the default 600 CPU-s and reports hung). A script replays in a scratch test (`differential::holds_on(0, 3, 4, &script, String::new(), false)`: full size is 3 accounts over 4 nodes). Each script below fails that way on main.

| Class | Seeds (full size) |
|---|---|
| A heard head goes stale: no Head is asked again once the peer's head moves | 29 |
| A stub granted read tests nothing for it | 86 |
| A thing the public syncs, strong from a dependent of a read thing: nothing held | 68 |
| A store kept unread at an older step than its readers' head | 45 |
| Must-hold bodies with no entry at quiet | 35 |
| Not shrunk anew (their shrunk scripts pass on main) | 15, 99 |
| Entries waiting for a read secret, not parked | none at full size; small size `OSIS_SYNC_START=940149075780` |

## A heard head goes stale (29)
`New(3), Run, Give(0, 0, Holder::Node(2), Syncs), Strong(2, None, 0), Revoke(0, 0, Holder::Node(2)), New(0), Run, Give(3, 1, Holder::Node(2), Syncs), Give(3, 0, Holder::Thing(1), Syncs), Revoke(3, 1, Holder::Node(2)), Give(3, 0, Holder::Node(2), Reads)`: node 2 holds thing 0 as a stub with no secret and a path heard by Head (three steps). Removing it from thing 1 rotates thing 0 again (thing 1 held sync there), so the read grant's claim is bound to a fourth step. Node 2's claim keys are at the heard head, which the sources no longer show, and it never asks Head again: spec/sync-opens.md §5 asks Head "once per change of S there", and nothing at node 2 changed (`Opens::ask_head` keys the ask by `changed_at(S)`). The open rule is fine; the tester never learns the head moved. Options:
- **Ask again at each filter generation**: a filter arrival on a connection asks Head for each S held there with no current path whose tested claim keys the filter shows none of. Rare-path brute force (notes/principles.md, Rare paths), but it costs O(such S) per generation, the waiting S times the peer's filter churn.
- **The grant says where its claim is**: a grant signal (spec/sync-inbox.md §5) carries the step its claim is bound to; the grantee hears the path from it (a step verifies on its own path from genesis), so its claim keys move to that step and it tests once. Covers grants with a signal only (a holder's admins enable `grant@~0`), so a re-seal or a grant without one still needs the first.

## A stub granted read tests nothing (86)
`New(1), Give(1, 0, Holder::Node(0), Syncs), Revoke(1, 0, Holder::Node(0)), Run, NewIn(1, 0), New(1), NewIn(1, 2), Give(1, 3, Holder::Node(0), Reads), Strong(1, Some(3), 0), Give(1, 0, Holder::Node(0), Reads), Strong(0, None, 3)`: node 0 ends with thing 0 as a stub (`contexts {Stub}`), no secret and no sync ID by a cut, and sends nothing for thing 0's sync ID after the first Run, though thing 0's head does not move after its read grant. Not diagnosed: check whether thing 0's sync ID is in node 0's sync set at all (`thing_sync_now` follows a stub only by a sync-only cut or a followed signal, spec/sync-set.md §2 Sync set says every held stub's), then whether its credentials carry its claim keys at the heard head.

## A public-synced thing reached through a dependent (68)
`New(0), NewIn(0, 0), New(2), New(3), Run, Give(3, 0, Holder::Node(2), Reads), Strong(2, None, 0), Give(0, 3, Holder::Public, Syncs), Strong(0, Some(1), 3)`: node 2 reads thing 0 and so its dependent thing 1; node 0 strongs thing 3, which the public syncs, from thing 1. The model keeps thing 3 unread at node 2 (spec/sync-set.md §2: a strong reaches it at sync, the public's role being every party's); node 2 holds nothing of it (`contexts {}`). Not diagnosed: whether thing 1's unit carries thing 3's stub under thing 0's sync ID, and whether node 2 takes the public's claim. Compare `differential::a_removed_reader_keeps_a_thing_the_public_syncs_unread_spec_sync_set_2` (the same with the strong in the independent's own unit).

## A store at an older step (45)
Full size only (not shrunk): node 1 keeps thing 0 unread at a step 3 deep while its readers' head is 5 deep, holding sync[4] by a claim (`node 1 keeps thing 0 unread at step .. (3 deep), its readers' head is 5 deep`). No reader registers the later steps there. Likely kin of the stale head above: the steps past node 1's key are registered only by a member at a store source (spec/sync-ids.md §6 Walk), and node 1 opens S only at a head it holds a key or claim for.

## Must-hold bodies with no entry at quiet (35)
`New(0), Pair(3), Partition(3, 1), Run, Give(4, 0, Holder::Node(1), Syncs), Give(3, 0, Holder::Node(1), Syncs), Inbox(4, Some(0)), Partition(3, 0), Run`: node 3 reads thing 0 with no source at all and lacks two bodies S must hold (`sources: {}`, `unheld: Some(4)`). Node 4 (node 3's account, paired) holds it and is reachable; nodes 3 and 4 each granted node 1 sync while partitioned. Not diagnosed.

## Not shrunk anew (15, 99)
Their shrunk scripts (a disk failure on a node paired with the reader; a Head lost to the pair rule) pass on main, the seeds still fail at full size with the same probe lines ("node 2 reads thing 0 unlike the reference"; "node 1's sync set holds thing 0 as Some(Stub), the model Some(Unread)"). Shrink each again; 15 shrinks to about 20 steps within the candidate budget.

## Entries waiting for a read secret, not parked
Small size `OSIS_SYNC_START=940149075780` ("node 1: entries waiting for a read secret, not parked"). Not shrunk.

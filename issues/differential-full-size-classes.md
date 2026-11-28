# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential at full size: 8 of 100 seeds fail, nearly all holding less than the model; one diagnosed cause (a stopped store has no way back in), the rest not shrunk; must-hold bodies with no entry at quiet (35); entries waiting for a read secret, not parked (small size only); the gate seeds tools/known_failures.txt lists.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes or delivery order change: work from the scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in two `tools/heavy` holds of 50 (`OSIS_SYNC_START=0`/`50`, `OSIS_SYNC_SEEDS=50`; about 460 s wall for both on a loaded box). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it (minutes in a hold; run it from a copied test binary so edits to the tree do not rebuild under it). A script replays in a scratch test (`differential::holds_on(0, accounts, nodes, &script, String::new(), false)`; full size is 3 accounts over 4 nodes).

| Class | Seeds (full size) |
|---|---|
| Holds less than the model: reads unlike the reference, or None or a stub where it keeps unread | 15, 29, 34, 45, 68, 86, 99 |
| Must-hold bodies with no entry at quiet | 35 |
| Entries waiting for a read secret, not parked | none at full size; small size `OSIS_SYNC_START=940149075780` |

## Holds less: a stopped store has no way back in (34, checked)
`New(0), Give(0, 0, Holder::Node(2), Syncs), Strong(2, None, 0), Run, Revoke(0, 0, Holder::Node(2)), Give(0, 0, Holder::Node(2), Reads)` (fails on seed 0's world at full size): node 2 keeps thing 0 unread, is removed and stops (spec/sync-judgement.md §6 Stops), then is granted read. It takes the grant's sync secret (epoch 3) but holds no commit of the thing, no roster and no open member of S anywhere. The spec has it keep S again and fetch S anew once a claim gives it the head's sync secret; the code gives no route to that claim (checked, core/sync):
- a stopped S takes nothing: `take_stamped` refuses every entry while `unheld` (store/mod.rs), and `take_unread` runs only after it;
- the stop's `drop_entries` removed the head-bound entries and their claim rows, so `unread::judge_s`'s stranded retry (`head_bound_entries`) finds none;
- stopped credentials have `step: None`, so `Creds::kept_unread` shows no claim key and answers no claim Hit (opens/holds.rs).
Resuming only follows `kept_sync_secrets` moving by another route or a raise to read; `streams::kept_again_fetches_anew_spec_sync_judgement_6` flips `set_unheld` by hand and covers the refetch, not the claim. Fix: a stopped S still tests and takes the entries bound to its head (and a newer head a source shows), keeping them under the source's budget, so a grant or re-seal at the head's epoch ends the stop; then a hand test from the script above.

## Holds less: the rest (not shrunk)
Probe lines: 15, 29 "node 2 reads thing 0 unlike the reference", 86 "node 0 reads thing 0 unlike the reference"; 45 and 68 "... sync set holds thing N as None, the model Some(Unread)"; 99 "... as Some(Stub), the model Some(Unread)". Shrink each and check it against the stop above first: several may be the same removal and re-grant. Small size: `OSIS_SYNC_START=2` ("node 0's sync set holds thing 0 as Some(Stub), the model Some(Unread)"), and the gate seed 527365123461 ("node 1 reads thing 1 unlike the reference").

## Other classes (not shrunk)
- Must-hold bodies with no entry at quiet (35): node 3 lacks the entry of a body S must hold.
- Entries waiting for a read secret, not parked: small size `OSIS_SYNC_START=940149075780` ("node 1: entries waiting for a read secret, not parked").

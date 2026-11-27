# Sync differential: failure classes beyond the gate's seeds
> Summary: the sync differential on held-model's stub closure (`Rule::BUILT`) at full size: 25 of 100 seeds fail, by class with what is known of each cause (the largest, a sync ID fork stranding the lesser side's grantees, is a design question), and the gate seed tools/known_failures.txt lists. Each class to become a hand-written test.
> Priority: normal
> Tags: sync, engine, tests

Seeds move whenever commit bytes change: work from scripts, and turn each class into a hand-written test (notes/principles.md, Never pin a seed). Replay a seed: `OSIS_FULL=1 OSIS_SYNC_START=<n> OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact differential::histories_hold_their_closure_plain`; the 100 run in one `tools/heavy` hold (about 210 s wall). A failing check prints the history as a script; `OSIS_SYNC_SHRINK=1` shrinks it (several shrinks side by side take a hold); a script replays in a scratch test (`differential::holds_on(0, 3, 4, &script, String::new(), false)`, full size). Most shrunk scripts below also fail on seed 0's world.

## Sync ID fork (design question)
Two nodes of one account, apart, each make a dependent thing X independent (each by a grant, or one by a grant and one by the public's), so each records its own sync ID (spec/sync-ids.md §2: both stand, X synced through the greatest). A grantee told on the lesser side's sync ID S1 holds S1 alone. Once its granter learns the greater S2 it syncs X through S2 and S1 leaves its sync set, so nobody serves S1: the grantee never takes the S2 side's role commits (its roster lacks their grants, its reads miss what they open) and never learns S2. Hand case: `differential::a_grantee_on_a_sync_id_forks_lesser_side_follows_the_greater_*` (ignored). Seeds 0, 5, 14 and 53 shrink to it (seed 0: `New(0), Run, Write(3, 0), Run, Give(3, 0, Node(1), Syncs), Give(0, 0, Node(1), Writes), Strong(1, None, 0)`), as does the gate seed.
- Before the rewrite a grant reached its holder's own sync ID, so the lesser side's grantee learned the other side's commits that way; nothing does now.
- Simplest option seen: a node reading X keeps syncing every sync ID of X it owns, not only the greatest (as a node keeping X unread already does), so the lesser side's grantee takes X's role commits under S1, among them the S2 side's making with its `sync.0`, and a re-seal by an admin boxes it at S2's epoch (a notice where it cannot open it by the wrap). Cost: every fork syncs twice for good, as "forks are permanent" allows. Unchecked: that the grantee then owns S2 (spec/sync-ids.md §4 Owner needs a sync secret of S2's steps, which the re-seal gives).

## Other classes (by first panic)
- **Reads unlike the reference** (48 70 85): unshrunk; may be the fork.
- **Stub, the model Unread** (2 15 25 31 84): a node holds a thing as a stub where the model keeps it unread. Hand case: `differential::a_removed_reader_keeps_the_publics_sync_secret_*` (ignored).
- **None, the model Stub** (24 52 81): the model holds a stub of a thing the node's sync set lacks.
- **Stub, the model None** (86): unshrunk. (Seed 45's script, a node reading another account's inbox, holds: a signal is followed only where its holder is read.)
- **None, the model Unread** (65 68): seed 65 shrinks (fails on seed 0's world too) to `New(0), Strong(2, None, 0), Give(0, 0, Node(2), Reads), New(0), NewIn(0, 1), Strong(0, Some(0), 2), Give(0, 1, Thing(0), Syncs)`: node 2 reads thing 0, which holds sync on thing 1 (an untold grant to a thing) and strongs thing 2, thing 1's dependent; the model keeps thing 1 unread at node 2 (thing 0's unit carries its stub), node 2 holds nothing of it. Cause not sorted.
- **Reads a thing the model does not hold** (20 34): unshrunk.
- One each, unshrunk: must-hold bodies a caught-up reader lacks at quiet (12); must-hold bodies with no entry at quiet (35); a storm past the cap (56); Unread, the model Stub (80).

## Small size
6 seeds: all hold. tools/known_failures.txt lists one gate seed against this issue: 527365123461, the fork (`New(2), Run, Give(0, 0, Node(1), Syncs), Give(2, 0, Public, Reads), Strong(1, None, 0)`).

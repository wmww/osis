# Option: grant a role without earlier history
> Summary: Every grant carries the history box, which opens every earlier epoch, so a new holder reads all retained content. Tess wants adding members without revealing history as a core option, not a chain of chats (notes/chat.md Left out, segments). Also useful for documents and folders, which cannot be segmented. Design below is model-checked (core/test/tla/rotation/Cut.tla): a cut rotation, a floor per keyset, and a carry rule on history entries.
> Priority: normal
> Tags: spec, permissions, keys, crypto, engine
> Queued: after net step 8 (or beside the late net steps when agents are free); design checked in the model, open questions below

History is a separate entry any holder of the old secret may add to a current epoch's history (spec/crypto.md §4, History add), and every rotation, grant and re-seal writes what its writer holds into the shared history box: without a rule change, any co-holder re-adds pre-grant secrets to the newcomer's epoch. A first sync (spec/sync.md §6) fetches what does not open last, after everything else; a holder with no old secrets would fetch and hold such bodies for nothing, so this option should stop that: the same stop a node-local cap would be (issues/partial-history-fetch.md).

`retention^.0` (spec/commits.md §5 The setting) must reach a history-less holder: its deltas are read like content, so a newcomer that cannot open an earlier epoch's setting does not know it: it shows and keeps history by no setting and fills no expiry or `final` from it. The grant must carry the setting in force or re-seal it.

This is not forward secrecy against a stolen device: that needs erasable per-device keys (notes/chat.md Rejected designs).

## Tess's decisions
- **Per grant, with a default**: a grant may say "without history"; a group or thing default is an aspect, set the way the history retention setting is (spec/commits.md §5 The setting).
- **Two choices only**: a newcomer sees history from when it was granted, or all of it. No admin-chosen start point.
- **Showing history later**: allowed if easy (it is a later grant with history to that holder).
- **Removed and re-added without history**: keeps what it could read before its removal, and must not get what was written between its removal and its re-add.
- **Metadata**: a newcomer may be able to tell that earlier entries exist (counts, sizes, times), but osis exposes none of it by default (no API surfaces entries the holder cannot open, nor counts of them).

## Design (checked in core/test/tla/rotation/Cut.tla)
Principle: a box or history entry hands a secret only to a party entitled to it; a holder granted without history is entitled to what follows its grant's cut. Every rule below is that principle applied to one writer of boxes or entries.

- **Cut**: a grant without history is, in the same commit, a read rotation (the cut) whose history entry carries no earlier secret (the names only, as every entry). It lists and supersedes like any rotation and boxes every current holder plus the grantee. A rotation removes only the boxes at epochs its history box carries, so the cut removes none: prior holders keep their boxes at the epochs it lists, which open everything before.
- **Floor**: each keyset carries a floor, one integer: a cut's own n; any other rotation's, the greatest floor among the epochs its keyset lists. A writer's word like the rest of the keyset: a hostile writer could lie, and gains nothing (it can box the old secrets directly).
- **Carry rule** (the History add change): a history entry at epoch e carries the secret of f only when f's floor is at least e's. It binds every writer of entries: the rotation's own history box, a grant's or re-seal's superset entry, and the History add. spec/crypto.md §4 History add becomes: a node holding e's secret, e established and not blocked at it, that holds an established superseded secret **of floor at least e's** that no live entry of the key lists, puts an entry carrying it. So no co-holder add, prior holder's later rotation, merge or re-seal brings a secret from below a cut into an epoch at or after it.
- **Boxing rule**: a holder whose newest grant is without history is boxed (rotation, grant, re-seal) only at epochs whose floor is at least its cut's n. Needed beside the carry rule: a node holding the grant may hold a fork made beside the cut by a rotator that did not know the grant (or may not have established the cut yet), and re-sealing the newcomer there hands it everything that fork's history box carries. A rotation by a node holding the grant always has such a floor; the rule bites on re-seals and grants. Its own nodes count no epoch below that floor as current (spec/crypto.md §4 Current gains the clause): never boxed such an epoch, a node holds one only as a commit it can read whose superseding chain it cannot (a re-added member holds its removal's rotation commit, wrapped under an epoch it kept), and it would show current with no secret (model, `X_readd` before the clause).
- **Dropped epochs**: those a held rotation lists but may not carry (floor below the rotation's): what a cut lists, and a fork beside a cut that a later merge lists. Nothing re-seals them into later epochs; their holders keep their boxes. A grant with history boxes the grantee at each current epoch and at each dropped epoch it holds. The **tip add** (the History add's per-holder form): a holder of a dropped epoch boxes it to a current holder allowed it (boxing rule) that, from the live boxes and entries the node holds, cannot open it. Showing history later is a grant with history.
- **Re-placing role commits**: a history-less holder cannot open blobs wrapped under epochs below its floor, yet must hold every commit a rotation names (Established) and the roster. A rotation places again, under its own epoch and projected to their `roles.0` deltas, the role commits on the actor it holds that are wrapped only under epochs below its floor: at a cut, the actor's role history; at a merge or due rotation over a fork beside a cut, that fork's role commits. Projected, because a removal commit carries its rotation's keyset: held whole without the chain that supersedes it, it shows that pre-cut epoch as current at the newcomer (model, `X_names` before the projection). Chain certificates likewise (about 11.5 KB per member).
- **Re-added without history**: the re-add is a cut. The member's nodes keep the secrets they hold from before the removal (a secret once shared cannot be un-shared); its absence gives it nothing: epochs made knowing the removal sit below the re-add's floor unless they follow the re-add.
- **Also**: a holder skips fetching bodies it cannot open (issues/partial-history-fetch.md); the retention setting in force reaches it (the grant carries or re-seals it).
- **Cost**: one integer per keyset. Per cut: prior holders' boxes at the epochs it lists stay (one per holder per role), and the actor's role commits are placed again projected (grows with cuts times roster). A grant with history writes one box per dropped epoch (grows with cuts and cut-adjacent forks, not writes).

### What a newcomer gets
- Never a secret of an epoch in its grant's causal past (made before the cut's rotator held the grant).
- Every epoch that follows its cut, from the live state alone (a new node of it included).
- Content written beside the grant, on a fork whose rotator did not know it, never reaches it, merge or not: that fork's history box opens the past.
- Content written beside the grant under another cut of at least the same n (two history-less grants racing) does reach it once merged: content beside the grant, never before it (`StrictNoPast` probe).

### Model (Cut.tla)
One actor, one key role. Admins a (the merger) and b rotate, grant, remove, re-seal and merge; readers add history; commits arrive in any order a node can read them (wrapped under an epoch it holds, boxing or granting it, or placed again projected). Know(x): every secret x ever opens from any box or entry ever written; Fresh(x): what a new node of x opens from the live boxes. Sizes and times: core/test/tla/rotation/README.md (History cuts). Properties: `NoPast` (property 1), `PriorKeep` (settled: every holder with history, prior holders included, opens every epoch from the live state; property 2), `NoAbsence` (property 3), `NewReads`, `Unlocked`, `Alike` (settled: every holder holds every current epoch, established, all alike; property 4), over the concurrent shapes of property 5.

| cfg | shape | result |
|---|---|---|
| `X_cut` | a cuts for n; b rotates beside it; reader p adds; a merges (fork merge across a cut) | pass |
| `X_race` | a grant with history (g) racing one without (n) | pass |
| `X_rmrace` | a cut racing the removal of m, each by either admin; merge and due rotation | pass |
| `X_readd` | m removed, re-added without history; b rotates beside it | pass |
| `X_two` | two concurrent cuts, merged | pass |
| `X_later` | showing history later; b rotates; p adds | pass |
| `X_names` | a cut naming an earlier removal | pass |
| `X_cut_old`, `X_readd_old` | no floor at all (today's rules) | fail `NoPast` (a's next rotation carries the pre-cut secret), `NoAbsence` |
| `X_cut_oldadd` | only the History add as today | fail `NoPast` (a co-holder adds epoch 0 at the cut) |
| `X_cut_nocarry` | carry rule off | fail `NoPast` |
| `X_cut_nofloor` | boxing rule off | fail `NoPast` (b, holding its fork beside the cut, re-seals n at it) |
| `X_names_noreplace` | no re-placing | fail `Unlocked` (n never meets the cut's names) |
| `X_two_strict`, `X_readd_fresh` | probes | fail as stated (open questions 1, 2) |

Not modelled: holder actors (Seal, left-out, stale), withdraw, void names, compaction snapshots (a `keys.0` snapshot's keyset must carry the floor), labels and steps.

### Open questions
1. **A re-added member's new node** (`X_readd_fresh` fails `ReaddFresh`): the removal's rotation removed the member's boxes, so a node it adds after its re-add without history reads nothing from before its removal; its existing nodes keep those secrets. Fix if wanted: the re-add also boxes the member at the epochs its removal's rotation listed (one box per such epoch; their history boxes open the rest, within its earlier entitlement). Tess: does "keeps what it could read before its removal" cover the account's new devices, or only what its devices hold?
2. **Concurrent cuts** (`X_two_strict`): a newcomer reads content written beside its grant under a racing history-less grant's fork. Never content from before its grant. Taken as the simple rule unless Tess objects.
3. **Labels and steps** (build): spec/sync.md §2 Role keys in use assumes every holder holds older secrets by history; a history-less holder opens from its cut's step on, and a walk to an older step must not strand it. Not modelled.

# The staged plan for the account redesign
> Summary: The staged plan for accounts on the ordinary rules, on the built sync unit (a thing's readable closure, so a thing may be carried under several sync IDs): Tess's answers it rests on, the stages (built ones cut to what they still owe; for the rest what each changes, removes, is checked by and unblocks), why they are ordered as they are, what is deleted when, what every other priority does meanwhile, and the risks. The order of work is notes/handoff.md's route: A4 next, on main, then what A2 owes, then A3, A5, A6, Z.

Designs: notes/account-membership-design.md, notes/write-path-design.md. The sync unit they are stated for is the built one (spec/sync-set.md §2, spec/sync-judgement.md §1-§2); one independent thing per unit was rejected (notes/sync-unit-scope.md, a record). Model: roles-model `paths`, notes/path-model-findings.md. A stage built says so in its State. Marks: **[checked: ref]** read there for this plan; **[assumed]** taken from a design note or not verified; everything unmarked about the future is the plan.

## Questions for Tess
Answered last (Tess): a delete-key commitment may be reused across an author's blobs within one unit (about 33 B a commit; a node keeping the unit unread can then tell which of its blobs one author can delete, and nothing across units); it is built with the slimming pass after A1 (notes/thing-cost.md, Delete keys per commit). Which unit's commitment a blob carried under several sync IDs takes is that pass's to state.

Answered and planned on (issues/actors-one-mechanism.md Answers): a removal reaches a far thing with that thing's next key rotation and where a node holds both it and a write it judges, never delivered for its own sake; nothing vouches for a role write (issues/role-vouch-contested.md: an unlisted one is dropped and a node that received it tells its user); nothing nobody received is kept; core removes a node when told and never waits, with no hear-out operation tied to removal (a general "wait until every connected node is fully synced" behind a sync button serves a node being retired: UX, later); the last admin is a writer's check only, no rule every node judges, and a timed admin grant does not count as a standing admin for it; a key that signs is a signing key, a value and never a thing, holding an ordinary grant on the thing it signs as and outranking nothing (notes/terms.md; a key that takes a thing back from its admins is parked: issues/recovery-design.md); may-grant is a flag; a write judged invalid is dropped at once as built, nothing kept aside for it and no drop waiting for a complete pass; the dial aspect is core's; a public thing's deposit budget stays open to everyone (keeping the seed from public would mean moving it, not a check in one place). A node keeping units unread may learn which of them share a writer and may know the account it works for (billing, abuse); neither route is hidden, and spec/requirements.md says so (a privacy pass may come someday: issues/sync-units-linked-at-rest.md). Node signers show on public things (a profile's evidence names which signer made each change): accepted with visible mode; a shared signer for a profile comes if and when shared keys are built.

## The stages at a glance
| | stage | needs |
|---|---|---|
| G | Main's failing properties | |
| S1 | Cost defects of many sync IDs | |
| S2 | External signals (built) | |
| S3 | Removal gaps on today's rules | |
| M1 | Model: the write path (roles-model `paths`) | |
| A1 | Stated paths and the purge author: the walk switched on (built) | M1 |
| A2 | Evidence per sync unit, grants with the thing granted (the sync rewrite, built) | A1 |
| A4 | Accounts as ordinary things, signing keys | A2 |
| A3 | A removal as evidence: what A2 left | A4 |
| A5 | Public things, cards, externally grantable | A4 |
| A6 | Core without accounts: the library (one stage with A5, library first) | A4 |
| Z | Clean-up | A6 |

One lane through the A stages, in the table's order (A4 before A3), with what A2 owes between A4 and A3: that is notes/handoff.md's route, which says where the lane stands. S1, S3, M1's leftovers and the long tail are not on it: beside work only. Nothing new is built beside old code until the piece before it is switched on (Tess): code built unused on an earlier piece changes under it.

## The order of the account redesign
- **Nothing waits on the sync unit.** Every stage is stated for the built unit, where a thing may be carried under several sync IDs: evidence goes under each sync ID that carries a commit, a removal with it where it is evidence of a held write. Validity is judged from held commits whatever sync ID brought them.
- **S1 is independent**: it fixes work per sync ID held, which every closure pays.
- **Paths (A1) before members (A4).** A node acting as a thing of its own needs a path of at least [A]. With paths first, the thing a node signs as is simply what a path starts at, so A1 lands with accounts unchanged.
- **Evidence (A2) before the removal's logging (A3)**: a removal's copy under a unit is carried with the evidence that needs it.
- **Accounts (A4) straight after A2 (Tess).** A2's Interim placements of an account's key part exist because accounts are not ordinary things, so they are replaced, not finished. A4 deletes the account's own lists and listings and rests on a removal carried as evidence, whole with its list: that is A2's derivation already. A4's stolen-node tests are its check; one failing for want of A3's required-set rule pulls that rule into A4.
- **A3 after A4**: what it has left (spec trims, the counts) changes no rule A4 reads.
- **Public things and cards (A5) with the library (A6), the library crate first**, so the account functions are written once, in the library, in their final shape.
- **Earliest deletion**: what a stage replaces goes at its start. Nothing old is kept beside its replacement inside a stage: formats change in place.

## Stages
Each stage is built on main, old code deleted first, one piece a session, each piece pushed (notes/coordination.md, Keep it simple and Rewriting an area); one review and gate at a stage's end.

### G. Main's failing properties
notes/priorities.md, Failing on main (tools/known_failures.txt): beside the lane, not before it.

### S1. Cost defects of many sync IDs
Any time; nothing waits on it. Built: an idle reconnect's judgements, bytes, members moved and store rows are flat (idle.rs); a new reader logs no copy of what its sources hold and a blob is fetched once whatever sync IDs announce it (first.rs). Left: a Fetch naming several sync IDs (it changes the wire: Fetch groups blob IDs by sync ID; built once, it exposed a caught-up race: a Pull names a cursor received, not stored), step verifications and store rows per member, and what issues/many-sync-ids-cost.md To fix lists (opens' filter reload, `Store::next_wake`'s rows per input, the first reconnect after first contact). Checked by osis-sync default tests counting at n and 10n.

### S2. External signals: what is left
Built (spec/permissions.md §5.2 External fires; spec/commits.md §5 The setting; spec/sync-inbox.md §1-§2).
- **For A5**: cards, KEM keys following the switch, refusing at the granter a grant to a holder that takes no grants from outside (spec/permissions.md §2 Granting to a thing, §5.2 External fires).
- **Owed**: the held-set property does not reach external fires (issues/held-set-external-fires.md); issues/external-signal-floor.md.

### S3. Removal gaps on today's rules
Each is a gap of the ordinary rules, fixed for every holder.
- *Addenda* (spec/permissions.md §5.2 Addenda): built in perm and engine (`flows::addenda`). Left: held-model, the §5.5 reading of admin-only content against a rotation.
- *A standing dispute*: an epoch covering a departure the node's walk does not apply is the other side's (spec/crypto.md §4; notes/account-membership-design.md §1, `takes`). Engine rotation, the rotation property, the TLA rotation models where they hold the withdraw rule (which .tla: not established).
- *The removal's result in the API*: what the removed party had added, removed or lowered; what arrived unnamed and was discarded. `osis`, CLI, app (notes/app.md).
- **A list naming X's lowering of the remover voids the removal**: the remover leaves out what the removal would not apply with, in the order received (notes/account-membership-design.md §4, The list); spec/permissions.md §5.1 Frontier gains the condition, and the engine's list building follows.
- Built: the last admin as the writer's refusal (notes/permissions.md, The last admin). Dropped: the overlap rule among valid commits only (issues/overlap-among-valid-commits.md).
- **Checked by**: the roles-model differentials in osis-perm, the addenda differential, `held_set_decides`, a hand reproducer per gap.

### M1. Model: the write path
roles-model `paths` holds the decided rules under `Rules::fixed` (core/test/roles-model/README.md, Paths; every finding with its counts in notes/path-model-findings.md), and A1's walk is differentially tested against it (notes/perm-paths.md). Accepted and counted: a write that applies nowhere can decide a fight among admins unshown (findings 34 to 36; notes/disputes.md); an end date on admin is no lowering (finding 38).
- **Left**: accomplices granted inside the theft window, sessions and overlapping dots as far as path rules touch them, bodies and refetching after a cover falls, addenda for purge requests (notes/a1-spec/README.md Open 20); a removal's units (logged where the signer could write, absent where it could only read, under every sync ID carrying such a thing, a holder raised to write after the removal, a promotion while it is on its way: for A3); public and external grants (notes/write-path-design.md §6: for A5).
- **Checked by**: `cargo run --bin roles-model -- N paths` through `tools/heavy`, each new rule with its negative control.

### A1. Stated paths and the purge author: what is left
Built: the walk (notes/perm-paths.md); settled readings: notes/a1-spec/README.md. Left:
- the purge-author indexes along stated paths (issues/stated-path-certificates.md);
- the walk's store over the engine's index, and an open rebuilding the walk from every header (issues/perm-eval-cost.md);
- the rest the engine reads short of the spec (notes/perm-paths.md, Read short of the spec);
- vouches for purge requests, if notes/a1-spec/README.md Open 20 settles that way;

### A2. Evidence per sync unit, grants with the thing granted: what is left
Built, on main, unreviewed and ungated: notes/holder-access-study.md (grants belong to the thing granted, offers, held for keys), notes/evidence-derivation.md (certificate copies per (commit, thing), re-derived at every change), notes/delete-keys.md. What it owes, taken after A4: notes/sync-rewrite-state.md, Next. Open questions: notes/a2-spec/README.md. A4's "members enter what A holds roles on by its boxes under A's sync ID" is held for keys at a node's first hop.
- **Checked by**: `held_set_decides`' held-model comparison and the sync differential; stored bytes per sync ID against issues/many-sync-ids-cost.md.

### A3. A removal as evidence
The list stays in the removal, as built (notes/write-path-design.md §2, E4); per-thing leaves are not the design. What is left: notes/a3-spec/README.md.
- **Changes**: spec/crypto.md §4 Carried demotions (logged by the required set, each whole with its list), a removal's copy in a unit's required set while the unit holds a write it judges, leaving with the last of them. It arrives with the thing's next key rotation by a writer holding it, by any node holding both it and a write it judges there, and, if built, by a node that only reads the thing depositing it once a writer syncing the thing logs the deposit (write-path §2 D4, promoted form). Nothing delivers a removal for its own sake (Tess); the gap is issues/removed-key-writes-show-far.md.
- **Briefs**: (1) spec; (2) the required-set rule for a removal's copy and the keyset seed; (3) counting: bytes a unit stores and a reader fetches per removal at n and 10n listed commits, and that copies leave.
- **Depends on**: A4.

### A4. Accounts as ordinary things
Next (Tess), on main with no branch. The builder's brief, read from the tree A2 leaves (the delete list with sizes, the order of work, the risks): notes/accounts-switch-brief.md. It builds on notes/stubs.md.

The flag day of the redesign: an account is an independent thing A, its members things holding roles on it: a node's thing minted with its key (its node thing, or one per account where a node wants its accounts unlinked). A's sync unit is its readable closure: A (which is home), its dependents (the account's private things), and what A reads that their strongs reach. The spec is written (notes/accounts-switch-brief.md, which holds the decisions and what lands when).
- **Changes**: spec/permissions.md, spec/crypto.md §3, spec/wire.md §4, spec/sync-set.md §1, spec/sync-inbox.md §1, spec/sync-opens.md §2 (a proof of a signer), spec/sync-ids.md §3 (a signer listed in A's steps by a claim under its own key); engine: making an account mints A with the first signer, pairing is a grant with a step and the pairer's trust entries, removing a node is the ordinary removal, a thing minted with A is its dependent; the `osis` account calls keep their names over the new mechanism (they move at A6); CLI and app follow.
- **Removed** (spec and code, with the delete piece): the account machinery that kept accounts apart from things (issues/deprecated-terms.md, Gone), the header's account fields and inner signature, their models and tests. What remains to build is in notes/accounts-switch-brief.md.
- **Kept on purpose**: notes/account-membership-design.md §7, Node anonymity as it was built (Tess); it stops saying "while they stand" of the spec sections once they go.
- **Briefs** (on main, delete first: notes/coordination.md, Rewriting an area): (1) spec; (2) keys: the key-grant aspect, a commit signed as the thing its key holds a grant on, minting with a key, the walk reading the key hop's value and the edge writes on it; (3) making an account and its things as dependents; (4) pairing; (5) removing a node, with the stolen-node walk of notes/account-membership-design.md §2 as tests; (6) the deletions in engine and perm; (7) `osis`, CLI, app adapted; (8) models and differentials: custody and epochs removed, the membership instances of M1 as the perm differential, sims' worlds rebuilt; (9) counting: a commit's bytes (no epoch, no inner signature), pairing and removal at n and 10n nodes.
- **Checked by**: the osis-perm differential against `paths` with the membership instances; the rotation and deep-departure properties on accounts as holders; sync differential and sims with accounts as ordinary things; `-p osis`, CLI and app tests; gate; the networking check.
- **Unblocks**: A5, A6; zero-growth's durable counters per signer; a key written down for an account (an admin key like any; a key no admin can remove is parked: issues/recovery-design.md).

### A5. Public things, cards, externally grantable
Built as one stage with A6, the library crate first (A6's account calls are the ones A5 rewrites). The spec is written; the builder's brief (the design, decisions, delete list, pieces in order, model, costs, risks): notes/public-and-cards-brief.md.
- **Changes**: the public as a holder that is no thing (zero tid, open boxes, public entry), every thing's keys opening what the public reads with public pieces carried by referring units, cards (`card.0`: a thing's keys and inbox as data), external signals on any thing, KEM keys only where sealed to, the granter's checks, public links.
- **Checked by**: held-model `closure::public` (built); sims: a profile fetched by a reader served only by a node keeping the referrer unread; a stranger's sealed fire reaching an inbox kept unread and promoted; bytes per independent thing against notes/thing-cost.md; a commit on a profile referenced from n and 10n units.
- **Unblocks**: the two leaks of priorities item 3 are judged again here.

### A6. Core without accounts
With A5 (above): the library crate and the account calls move first, and A4's pairing and node-removal pieces are built there, not in `osis` (notes/public-and-cards-brief.md, A6 folded in).
- **Changes**: the library crate (osis-account, libs/account) holds making an account, pairing, nodes and their removal, the profile, contact cards [built: notes/public-and-cards-brief.md piece 2]; core keeps signers, a session's default path and purge author (`author()`), and the dial aspect (`publish_dial_on`) (notes/write-path-design.md §5 table). The schema describes a realm, a home and an account [built: schema/realm.osis, osis-account `Realm`, notes/realms.md]; profiles are public things, the dial list a contact-only thing. CLI `me`, `pair`, `contact` call the library; app and libs/kit follow (notes/app.md).
- **Removes**: the account calls from the `osis` crate; the sibling rule of dialing; "the account's inbox" as core's.
- **Briefs**: (1) the `osis` surface (notes/api-design.md); (2) the library crate; (3) schema: realm, home, account, profile, contacts; (4) dialing by the dial aspect; (5) CLI; (6) kit and app.
- **Depends on**: nothing open. **Unblocks**: realms' UX work; schema discovery and templates stay parked.

### Z. Clean-up
The renames left (below); notes/terms.md, Built and being moved to, reduced to what is true; issues closed or re-read; the TLA vocabulary pass with a TLC rerun; notes/overview.md and notes/architecture.md brought to the result.

## What is deleted, and when
| what | stage | must exist first |
|---|---|---|
| The inbox field of `keys.0`, KEM keys nobody seals to | A5 | cards |
| Account functions in the `osis` crate | A5/A6, first | the library crate |

The multi-unit carriage (a thing under every enclosing unit's sync ID, retag, deposits into enclosing units, per-sync-ID copies) stays: it is the built unit. Kept as records (Tess): node anonymity as built, notes/account-membership-design.md §7; the rejected sync unit, notes/sync-unit-scope.md.

## What the other priorities do meanwhile
By item of notes/priorities.md.
- **First, main's failing properties**: proceed first (G).
- **2. Whole commits tail**: invalid bodies kept at stores stays a Tess call and proceeds; "re-grants restoring from stores" matters more after S3, since an addendum arriving late fetches bodies again. Drop-rejoin's holder-logs-again proceeds on the built unit (it logs under every sync ID that carries the thing). Zero-growth: the tombstone design that needs a stable writer waits for A4 (each signer is one); its other rows proceed.
- **3. Key passing and grants without history**: history-less-grant's next step (records of dependent things under another's sync ID) proceeds. removed-node-reads-later-grants (both leaks) is judged at A5.
- **4. Bounded memory tail**: proceeds; it touches no stage.
- **5. Account signing tail**: overtaken at A4; the account signing issues and rotation-names-grow close there, maker-unknown-from-snapshot is re-read [assumed].
- **6. Slimmer things** (notes/thing-cost.md, Ranked candidates):
  - Free by a stage: 4 (no `epoch`, no inner signature: A4); the KEM keys most independent things publish (A5).
  - No longer free: 12 (`X/` only for a blob under several sync IDs) and 1 (store each commit once, beside per-sync-ID copies, which stay) are ordinary slimming work, to proceed; issues/enclosing-unit-commit-cost.md (the bytes a commit pays per enclosing unit beyond its entry) beside them.
  - Moot: `actor` absent when equal to `author` (14: A1 replaced both).
  - Wait: 3 and 13 (the echo, the blob ID beside an inline blob) until S1 settles the entry flow; 5, 6, 8 and the delete-key ideas (wire format of a commit) are done in one pass, with A4's header change, so the header changes once.
  - Proceed any time: 2, 7, 9, 10, 11 (engine rows).
  - perm-eval-cost: A1 Left; many-sync-ids-cost: S1; many-things-cost, derived-state-recomputed, chat-add-cost proceed.
- **7. Sync leftovers**: none closes without its fix; the multi-unit carriage they sit in stays. Need their fix: the retag items of sync-unbuilt and sync-tests-owed, the `rewrap` item of sync-pending-leftovers (its test), attach-cost; sync-parks-check, sync-tests-owed (deposit items), storage-owners and sync-models-lag proceed on their own; differential-full-size-classes needs its classes fixed (a required set hanging on other paths, a grant counting through certificates), each a design step of its own (its first fix is parked: it exposes three more); sync-only-reference is a design step under the built unit. Re-read with what A2 owes: cert-blob-hostile-delete. Wait for A5 and A6: stranger-fire-bounds, dial-candidates, sync-link-first-contact. Proceed: cover-before-commit, opens-hit-index-cost, timed-loss-wait.
- **8. Long tail**: proceeds beside; an issue in the perm walk (settled-writers-dispute-script, dispute-scan-cost) is checked against the stated-path walk before a fix.
- **Parked on Tess**: unchanged; recovery is parked (issues/recovery-design.md); settings and client auth do not collide.
- **Renames owed** (issues/deprecated-terms.md): `actor` in identifiers (holder actor) at A6 and Z, each use read; the TLA vocabulary at Z, with Account.tla's share gone at A4; the spec's rule words (edge, rights, demotion), unscheduled; the reference-graph words stay with their own rebuild.
- **Later designs that build on this**: readers hidden from each other (issues/readers-see-readers.md); hidden mode stays a design.

## The stage far larger than the rest
A4 (the account system replaced). On main, delete first, spec text written alongside (notes/coordination.md, Rewriting an area); its pieces in order are in notes/accounts-switch-brief.md, one a session. Its rules are modelled (roles-model `paths`: the key hop, the membership cases).

## Risks
1. **The path-judged walk does not hold up outside the modelled worlds** (sessions, bodies). Descent, `until`, self-removal by path end, removals of more than one hop, may-grant grants and finalizes (with a lowering judged on any fall), demotion to write, several edge writes per commit, purge authors and covers by copies hold in the model; a write that does not apply can decide a fight among admins unshown, with honest writers too (notes/path-model-findings.md 34 to 36: accepted, counted; notes/disputes.md). A void check reads each setter once (notes/a1-spec/README.md Open 2); the walk's cost shapes are counted at n and 10n (notes/perm-paths.md, Counts).
2. **Evidence over a thing under several sync IDs**: modelled (held-model `evidence`, notes/evidence-model-findings.md): copies re-derived from current holdings at every change hold, a thing under a root's sync ID and its own judged alike under each (fixed once at logging they leave a sync ID short: notes/evidence-model-findings.md 2). Left: a sim and differential against the built carriage (a reader holding one sync ID plus its paths' key parts judging as a node holding all, `World::joint`).
3. **Lazy delivery leaves a removed key's writes showing** in a thing no remaining member writes, at readers served only by stores, until a node holding the removal sees them there. Cheapest check: D2's model of the deposit on sight (notes/write-path-design.md §2, D4); else an issue.
5. **The walk read without trust differs from the trusted one wherever a removal's reach-back drops a write that acted**: a lowering applied at its key keeps its drops and stays applied when a later removal drops it or its author's grant (notes/path-model-findings.md 16), so a node trusting nothing reads otherwise than one trusting the removal, and is shown the removal as a dispute by the widened rule (a lowering whose trust changes the reading; honest histories raise none in the model). Most nodes trust nothing until a dispute is detected, so detection must catch these, at a walk per candidate lowering (Open 0). Counted: a dispute probe updates its candidate's component alone (notes/perm-paths.md, Counts); disputes raised in honest histories: none in the model.
6. **A public thing referenced from many units**: each commit on it is entered under every referring unit's sync ID (an entry and stamp each). Cheapest check: A5's count at n and 10n referrers; the cost is the built unit's, stated (issues/enclosing-unit-commit-cost.md).

## Not established
- Whether readers reject content sealed under a superseded read epoch.
- Which TLA rotation models hold the withdraw rule S3's standing dispute changes.
- The cost defects' causes (S1).
- Bytes of a removal's copy per sync ID, and of an evidence set per sync ID: to count in A3.

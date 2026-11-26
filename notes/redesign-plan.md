# The account redesign: what is left
> Summary: What the account redesign (accounts on the ordinary rules, on the built sync unit: a thing's readable closure, so a thing may be carried under several sync IDs) still owes after its built stages (A1 stated paths, A2 evidence per unit, A4 accounts as ordinary things, A5/A6 public things, cards and the account library): Tess's answers it rests on, the open stages (S1, S2, S3, M1, A1 and A2 leftovers, A3, clean-up) with what each changes and is checked by, risks, and what is not established. Order of work: notes/handoff.md, The route.

Designs: notes/account-membership-design.md, notes/write-path-design.md; built: notes/accounts-switch-brief.md, notes/public-and-cards-brief.md. The sync unit they are stated for is the built one (spec/sync-set.md §2, spec/sync-judgement.md §1-§2); one independent thing per unit was rejected (notes/sync-unit-scope.md, a record). Model: roles-model `paths`, notes/path-model-findings.md. Marks: **[checked: ref]** read there for this plan; **[assumed]** taken from a design note or not verified; everything unmarked about the future is the plan.

## Tess's answers it rests on
Answered last (Tess): a delete-key commitment may be reused across an author's blobs within one unit (about 33 B a commit; a node keeping the unit unread can then tell which of its blobs one author can delete, and nothing across units); it is built with the slimming pass after A1 (notes/thing-cost.md, Delete keys per commit). Which unit's commitment a blob carried under several sync IDs takes is that pass's to state.

Answered and planned on (issues/actors-one-mechanism.md Answers): a removal reaches a far thing with that thing's next key rotation and where a node holds both it and a write it judges, never delivered for its own sake; nothing vouches for a role write (issues/role-vouch-contested.md: an unlisted one is dropped and a node that received it tells its user); nothing nobody received is kept; core removes a node when told and never waits, with no hear-out operation tied to removal (a general "wait until every connected node is fully synced" behind a sync button serves a node being retired: UX, later); the last admin is a writer's check only, no rule every node judges, and a timed admin grant does not count as a standing admin for it; a key that signs is a signing key, a value and never a thing, holding an ordinary grant on the thing it signs as and outranking nothing (notes/terms.md; a key that takes a thing back from its admins is parked: issues/recovery-design.md); may-grant is a flag; a write judged invalid is dropped at once as built, nothing kept aside for it and no drop waiting for a complete pass; the dial aspect is core's; a public thing's deposit budget stays open to everyone (keeping the seed from public would mean moving it, not a check in one place). A node keeping units unread may learn which of them share a writer and may know the account it works for (billing, abuse); neither route is hidden, and spec/requirements.md says so (a privacy pass may come someday: issues/sync-units-linked-at-rest.md). Node signers show on public things (a profile's evidence names which signer made each change): accepted with visible mode; a shared signer for a profile comes if and when shared keys are built.

## The open stages
S1 cost defects of many sync IDs; S2 external signals, owed; S3 removal gaps on today's rules; M1 the write-path model, left; A1 stated paths, left; A2 evidence per sync unit, owed; A3 a removal as evidence; Z clean-up. None waits on another; the handoff's route says which runs when. Evidence goes under each sync ID that carries a commit, a removal with it where it is evidence of a held write; validity is judged from held commits whatever sync ID brought them.

## Stages
Each stage is built on main, old code deleted first (notes/coordination.md, Keep it simple and Rewriting an area).

### S1. Cost defects of many sync IDs
Any time; nothing waits on it. Built: an idle reconnect's judgements, bytes, members moved and store rows are flat (idle.rs); a new reader logs no copy of what its sources hold and a blob is fetched once whatever sync IDs announce it (first.rs). Left: a Fetch naming several sync IDs (it changes the wire: Fetch groups blob IDs by sync ID; built once, it exposed a caught-up race: a Pull names a cursor received, not stored), step verifications and store rows per member, and what issues/many-sync-ids-cost.md To fix lists (opens' filter reload, `Store::next_wake`'s rows per input, the first reconnect after first contact). Checked by osis-sync default tests counting at n and 10n.

### S2. External signals: what is owed
Built (spec/permissions.md §5.2 External fires; spec/commits.md §5 The setting; spec/sync-inbox.md §1-§2).
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
- **Left**: accomplices granted inside the theft window, sessions and overlapping dots as far as path rules touch them, bodies and refetching after a cover falls, addenda for purge requests (notes/a1-spec/README.md Open 20); a removal's units (logged where the signer could write, absent where it could only read, under every sync ID carrying such a thing, a holder raised to write after the removal, a promotion while it is on its way: for A3); public and external grants (notes/write-path-design.md §6).
- **Checked by**: `cargo run --bin roles-model -- N paths` through `tools/heavy`, each new rule with its negative control.

### A1. Stated paths and the purge author: what is left
Built: the walk (notes/perm-paths.md); settled readings: notes/a1-spec/README.md. Left:
- the purge-author indexes along stated paths (issues/stated-path-certificates.md);
- the walk's store over the engine's index, and an open rebuilding the walk from every header (issues/perm-eval-cost.md);
- the rest the engine reads short of the spec (notes/perm-paths.md, Read short of the spec);
- vouches for purge requests, if notes/a1-spec/README.md Open 20 settles that way;

### A2. Evidence per sync unit, grants with the thing granted: what is owed
Built: notes/stubs.md (grants belong to the thing granted), notes/evidence-derivation.md (certificate copies per (commit, thing), re-derived at every change), notes/delete-keys.md. What it owes: notes/sync-rewrite-state.md, Next. Open questions: notes/a2-spec/README.md.
- **Checked by**: `held_set_decides`' held-model comparison and the sync differential; stored bytes per sync ID against issues/many-sync-ids-cost.md.

### A3. A removal as evidence
The list stays in the removal, as built (notes/write-path-design.md §2, E4); per-thing leaves are not the design. What is left: notes/a3-spec/README.md.
- **Changes**: spec/crypto.md §4 Carried demotions (logged by the required set, each whole with its list), a removal's copy in a unit's required set while the unit holds a write it judges, leaving with the last of them. It arrives with the thing's next key rotation by a writer holding it, by any node holding both it and a write it judges there, and, if built, by a node that only reads the thing depositing it once a writer syncing the thing logs the deposit (write-path §2 D4, promoted form). Nothing delivers a removal for its own sake (Tess); the gap is issues/removed-key-writes-show-far.md.
- **Pieces**: (1) spec; (2) the required-set rule for a removal's copy and the keyset seed; (3) counting: bytes a unit stores and a reader fetches per removal at n and 10n listed commits, and that copies leave.

### Z. Clean-up
Issues closed or re-read. Renames owed (issues/deprecated-terms.md): `actor` in identifiers (holder actor), each use read; the TLA vocabulary with a TLC rerun; the spec's rule words (edge, rights, demotion), unscheduled; the reference-graph words stay with their own rebuild. Later designs that build on the redesign: readers hidden from each other (issues/readers-see-readers.md); hidden mode stays a design.

## Risks
- **The path-judged walk does not hold up outside the modelled worlds** (sessions, bodies). Descent, `until`, self-removal by path end, removals of more than one hop, may-grant grants and finalizes (with a lowering judged on any fall), demotion to write, several edge writes per commit, purge authors and covers by copies hold in the model; a write that does not apply can decide a fight among admins unshown, with honest writers too (notes/path-model-findings.md 34 to 36: accepted, counted; notes/disputes.md). A void check reads each setter once (notes/a1-spec/README.md Open 2); the walk's cost shapes are counted at n and 10n (notes/perm-paths.md, Counts).
- **Evidence over a thing under several sync IDs**: modelled (held-model `evidence`, notes/evidence-model-findings.md): copies re-derived from current holdings at every change hold, a thing under a root's sync ID and its own judged alike under each (fixed once at logging they leave a sync ID short: notes/evidence-model-findings.md 2).
- **Lazy delivery leaves a removed key's writes showing** in a thing no remaining member writes, at readers served only by stores, until a node holding the removal sees them there. Cheapest check: D2's model of the deposit on sight (notes/write-path-design.md §2, D4); else an issue.
- **The walk read without trust differs from the trusted one wherever a removal's reach-back drops a write that acted**: a lowering applied at its key keeps its drops and stays applied when a later removal drops it or its author's grant (notes/path-model-findings.md 16), so a node trusting nothing reads otherwise than one trusting the removal, and is shown the removal as a dispute by the widened rule (a lowering whose trust changes the reading; honest histories raise none in the model). Most nodes trust nothing until a dispute is detected, so detection must catch these, at a walk per candidate lowering (Open 0). Counted: a dispute probe updates its candidate's component alone (notes/perm-paths.md, Counts); disputes raised in honest histories: none in the model.
- **A public thing referenced from many units**: each commit on it is entered under every referring unit's sync ID (an entry and stamp each): counted exactly one per referrer at n and 10n (notes/thing-cost.md); the built unit's cost, accepted (issues/enclosing-unit-commit-cost.md).

## Not established
- Whether readers reject content sealed under a superseded read epoch.
- Which TLA rotation models hold the withdraw rule S3's standing dispute changes.
- The cost defects' causes (S1).
- Bytes of a removal's copy per sync ID, and of an evidence set per sync ID: to count in A3.

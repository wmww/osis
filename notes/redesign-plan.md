# The staged plan for the two redesigns
> Summary: The one plan a coordinator builds from for accounts on the ordinary rules and for the sync unit as one independent thing and its dependents: Tess's answers it rests on, the stages in order (what each changes, removes, needs modelled or measured, how it is checked, what it unblocks), why the two are ordered as they are, what is deleted when, what every other priority does meanwhile, and the risks with their cheapest early checks.

Designs: notes/account-membership-design.md, notes/write-path-design.md (accounts, "(a)"); notes/sync-unit-scope.md, notes/sync-unit-design.md (the unit, "(b)"); where they meet: notes/sync-unit-design.md §12. Model of (a): roles-model `paths`, notes/path-model-findings.md. Nothing below is built. Marks: **[checked: ref]** read there for this plan; **[assumed]** taken from a design note or not verified; everything unmarked about the future is the plan.

## Questions for Tess
Four open, from the unit's model and design (notes/closure-model.md, The unit model; notes/sync-unit-design.md); each names the rule the plan proceeds on, and none holds a stage back:
1. **Does a unit let go of a dependent thing it no longer references?** (issues/unit-dependent-release.md) Proceeding on yes: a unit holds a dependent thing while it references it, as built. Reaches M1 and B2; the other answer is a deletion.
2. **Must a role held through a group work when nothing held references the group?** (issues/unit-key-paths.md) Proceeding on no: a role through a holder counts while the closure holds the holder; the key-path variant is modelled, fails two findings and is not planned. Reaches nothing further unless Tess asks for a new design of it.
3. **May a reference to a thing inside a realm, written from a bare ID by a node that never held the thing, bring nothing?** (issues/unit-reference-home.md) Proceeding on yes: a strong brings a dependent thing's unit by the home written beside it, which its writer fills whenever it holds the thing or copies a reference that had one. Reaches M1, B1; the other answers are a deletion (no homes: no strong to a dependent thing brings its unit) or a blob per dependent thing in every unit.
4. **What may a node keeping data unread learn about references and grants?** (issues/unit-keeper-learns.md) Proceeding on: an opaque handle per referenced thing, and how many things each kept thing was granted. Reaches B1's spec brief (spec/requirements.md, Data a node cannot read).

Answered last (Tess): a delete-key commitment may be reused across an author's blobs within one unit (about 33 B a commit; a node keeping the unit unread can then tell which of its blobs one author can delete, and nothing across units); it is built with the slimming pass after A1 (notes/thing-cost.md, Delete keys per commit).

Answered and planned on (issues/actors-one-mechanism.md Answers, issues/sync-unit-dependent-tree.md): a removal is logged where an act of the removed node could be valid, for good; vouching for role writes is automatic; nothing nobody received is kept; a strong to a dependent thing brings its independent's unit; core removes a node when told and never waits, with no hear-out operation tied to removal (a general "wait until every connected node is fully synced" behind a sync button serves a node being retired: UX, later); a timed admin grant does not count as a standing admin for the last-admin rule; the dial aspect is core's; a public thing's deposit budget stays open to everyone (keeping the seed from public would mean moving it, not a check in one place); at a promotion the thing's blobs go under the new sync ID as they are, an entry each, provided that is the easy build. A holder thing gets a member's sync secret from the member's steps, sealed by the step's X25519 exchange (about 48 B, not quantum-resistant: it guards the member list and the right to fetch ciphertext, never content, so it is not a secret that must last for years); the read secret stays out of steps in this change. A referrer holding only sync on its target still brings it, kept unread by whoever syncs the referrer (spec/requirements.md Data model says "can itself sync"). A unit the remover does not administer goes on serving a removed holder its ciphertext until one of its admins issues a step: accepted, and to be closed whenever an easy way is seen. A node keeping units unread may learn which of them share a writer and may know the account it works for (billing, abuse); neither route is hidden, and spec/requirements.md says so (a privacy pass may come someday: issues/sync-units-linked-at-rest.md). Node signers show on public things (a profile's evidence names which signer made each change): accepted with visible mode; a shared signer for a profile comes if and when shared keys are built.

## The stages at a glance
| | stage | needs | redesign |
|---|---|---|---|
| G | Main's failing properties | | neither |
| S1 | Cost defects of many sync IDs | | before either |
| S2 | External signals: the word, and fires valid only where enabled | | before either |
| S3 | Removal gaps on today's rules | M2 brief 1 | before either |
| M1 | Model: the unit, handle and key blobs, promotion (held-model) | | (b) |
| M2 | Model: the write path's second round (roles-model `paths`) | | (a) |
| M3 | Model: evidence completeness (held-model) | M1, M2 | both |
| B1 | Holder things in steps, handle and key blobs, homes, the walk | M1, S1 | (b), additive |
| A1 | Stated paths and the purge author, judged in osis-perm | M2 | (a) |
| B2 | The switch: a unit is one independent thing and its dependents | B1 | (b) |
| B3 | Status and waits over a closure | B2 | (b) |
| A2 | Evidence per unit | A1, B2, M3 | both |
| A3 | A removal's list and where it is logged | A2 | both |
| A4 | Accounts as ordinary things | A3 | (a) |
| A5 | Public things, cards, externally grantable | A4 | both |
| A6 | Core without accounts: the library | A5 | (a) |
| Z | Clean-up | A6 | |

Parallel lanes: {S1, S2, S3, M1, M2} at once; then B1 beside A1 (sync and engine against perm and commit); B2 then B3; A2 onward is one lane.

## The order of the two redesigns
- **Independent of (a)**: S1, M1, B1, B2, B3. The unit's definition reads roles and records only, and today's account root is a root like any [checked: spec/sync-set.md §2, the unit is defined from strongs, roles and records; assumed: nothing in the switch reads the signing chain].
- **Independent of (b)**: S2, S3, M2, A1. Validity is judged from held commits whatever sync ID brought them.
- **(b)'s switch before (a)'s evidence.** Evidence per unit, a removal logged per unit and the enumeration of a removed signer's units are each stated once per unit only when a thing is under one unit (notes/sync-unit-scope.md, wins). Built on the readable-closure unit they would need the case of a thing under several sync IDs, then lose it: built twice. The other way round, B2 only shrinks certificate placement to "outside the unit" [assumed: notes/sync-unit-design.md §1], which is deletion, and A2 then replaces what is left.
- **Paths (A1) before members (A4).** A signer that is not the account needs a path of at least [A]; today's header has one `actor` [checked: spec/wire.md §4]. With paths first, today's account key is simply the signer of a path that starts above it, so A1 lands with accounts unchanged.
- **The ordinary removal complete (A3) before accounts rest on it (A4).** A4 deletes the account's own lists and listings; the per-thing list, the per-unit logging and vouches must hold first.
- **Public things and cards (A5) before the library (A6)**, so the account functions leave the `osis` crate once, in their final shape.
- **A1 before B2 is not required**; they run side by side. A1's one transitional piece: chain certificates certify the stated path instead of searching for one, a narrowing of engine `sync/certified.rs` that A2 deletes.
- **Earliest deletions**: the multi-unit carriage at B2, the signing chain at A4. Nothing old is kept beside its replacement inside a stage: formats change in place.

## Stages
Each brief ends at green commits and fits a session (notes/coordination.md, Briefs); a brief that turns out larger is split by its coordinator, never run long. "Gate" means the branch's reviewer runs `tools/gate.sh` once.

### G. Main's failing properties
notes/priorities.md, First: issues/custody-pair-needs-write.md, issues/paged-apply-differs-from-whole.md, issues/held-set-decides-plain-record-only.md, issues/app-tile-unreadable-emails-test.md [checked: tools/known_failures.txt].

### S1. Cost defects of many sync IDs
Before either redesign; nothing waits on a question.
- **Changes**: sync and engine only; the spec already says what should hold [assumed: spec/sync-streams.md §4 Costs, Joining; spec/sync.md §2, as cited by notes/sync-unit-design.md §8]. No format change.
- **Briefs**: (1) the join per shared sync ID at an idle reconnect: find the cause, fix; (2) work per sync ID held at a commit and at an idle reconnect (`status: stranded`, `inbox: register judged`, `opens standing`, the store rows behind them); (3) opens found in one round batch at a first sync, and what a new reader sends back (23 KB per unit, unexplained).
- **Measure first**: nothing new; the figures are notes/sync-unit-design.md §8 [measured there, main at 6e38bcd03].
- **Checked by**: default tests in osis-sync counting at n and 10n (bytes, store rows read, the named counters), as §8's throwaway tests did; gate.
- **Unblocks**: B1 and B2, which make many sync IDs the normal case. Closes most of issues/many-sync-ids-cost.md (its Still to count stays).

### S2. External signals
Before either redesign.
- **Changes**: the rename open signal → external signal, open fire → external fire, "enables" (issues/deprecated-terms.md row; notes/terms.md): spec/data-model.md §2, spec/sync-inbox.md §2, spec/permissions.md §5.2 External fires, spec/commits.md §5 The setting; engine, perm, `osis`, CLI, schema, app text. The rule: a fire of an external signal by a party holding no write on the thing is valid iff the thing's current setting (the newest held valid `retention^.0`, whatever the fire's `ts`) names the signal in an entry of its own (spec/permissions.md §5.2 External fires; notes/write-path-design.md §4, The setting, External fires). An account's inbox already names its three signals at creation [checked: spec/sync-inbox.md §1], so accounts keep working; a thing that is its own inbox takes tickets, removal notices and stranded notices from parties holding no write on it only once its admins enable them.
- **Not in this stage**: cards, "externally grantable" as what a thing publishes, KEM keys following the switch: A5.
- **Briefs**: (1) the rename, one pass, each use read; (2) held-model and spec: fire validity by the setting; (3) engine and perm, `osis` enable call (notes/api-design.md), CLI; (4) first-party schema and app: which things enable which signal.
- **Model first**: held-model judges signals [checked: notes/test-properties.md, held-set property's coverage tally names "a judged signal"]; brief 2 adds the rule there before brief 3.
- **Checked by**: `held_set_decides` with its held-model comparison; a rule test that an unnamed fire reaches no listener and is not promoted; the sim scenarios; gate.
- **Unblocks**: A5; issues/stranger-fire-bounds.md is re-read after it.

### S3. Removal gaps on today's rules
Each is a gap of the ordinary rules, fixed for every holder; all land before either redesign except where said.
- **Briefs**:
  1. *Model* (part of M2, first): vouches under today's rule (authority as the walk gives it) in roles-model `edges` and `addenda` [checked: modules exist, core/test/roles-model/src], with addenda written when the right is first held.
  2. *Vouches*: spec/permissions.md §5.1 to §5.2 (the vouch aspect, the first walk, what counts), spec/wire.md; osis-perm (two walks for a component holding a counting vouch); engine writing (per thing, on applying a removal and on first holding the right); held-model. The voucher's authority is "an edge write of the same kind by it at the vouch's key would apply", so the check is whatever judges edge writes and survives A1 unchanged.
  3. *Addenda*: reach admin-only content that is not role-class; written again when the right is first held (re-granted, switched side).
  4. *A standing dispute*: an epoch covering a departure the node's walk does not apply is the other side's (spec/crypto.md §4; notes/account-membership-design.md §1, `takes`). Engine rotation, the rotation property, the TLA rotation models where they hold the withdraw rule [assumed: which .tla].
  5. *The last admin, locally*: the refusal for every thing, dependent or independent, and the mark that lets a thing go adminless: spec/permissions.md §1 to §2, spec/wire.md, engine `flows/edges.rs` (`leaves_no_admin` is dependents only [checked: core/engine/src/flows/edges.rs]), `osis` error and option, CLI. The rule every node judges alike waits for A1 (it names an edge of a stated path) and A2 (its evidence): built before them it would give readers and members different verdicts (notes/path-model-findings.md, 8).
  6. *The removal's result in the API*: what the removed party had added, removed or lowered; what arrived unnamed and was discarded. `osis`, CLI, app (notes/app.md). No keep.
  7. *The overlap rule among otherwise valid commits only* (spec/commits.md §4): modelled in held-model first; dropped from this stage if it makes validity read validity.
- **Not before the redesigns**: what no list keeps beyond today's first half ("R never demotes its own author") [checked: spec/permissions.md §5.1 step 4]: it reads the listing write's own path, which today's walk does not define (the any-path readings strike too much or stay gameable by backdating), so on today's walk a list naming X's lowering of the remover keeps it and voids the removal (core/test/roles-model/README.md, Vouches); the list as a leaf per thing with an entry per role commit (A3: its carriage is the evidence copy, so built before A2 it is built twice); "nobody vouches for its own signer's commit" (meaningful once a write has one path: A1); pairing handing over trust entries (A4).
- **Checked by**: the roles-model differentials in osis-perm (`tests/it/differential.rs`), the addenda differential, `held_set_decides`, hand reproducers for each gap, gate.
- **Depends on**: nothing open. **Unblocks**: A3 and A4, which then add no removal rule of their own.

### M1. Model: the unit
- held-model `unit` [checked: core/test/held-model/src/unit.rs, tests `spec_unit`] beside `closure`: the unit as one independent thing and the dependents it reaches; what a unit tells its sync holders as two derived sets, handles and keys, each a function of the unit (notes/sync-unit-design.md §2); one walk over them for readers and nodes keeping units unread.
- Modelled: the unit by reach and its release; the join's static claim (every reader of a unit computes its blobs alike; the walk over them enters what a reader served by all-seeing writers enters), with the reading it replaces (a blob naming the target's unit, key paths) kept as controls and its five findings pinned (notes/closure-model.md, The unit model).
- Modelled over time (notes/closure-model.md, The unit model): homes in the data, blobs at stores judged after a complete pass by writers with different holdings, no dependence on history, readers walking by the blobs, a hostile writer, forks, work at a change, each with its property and negative control; four findings against the design there (Findings against the design). To model before B1's code, promotion: every arrival order loses no body (a late writer, a late reader), no blob changes in a referrer, and the cases notes/sync-unit-design.md §5 leaves open (judged invalid, forked, a mixed commit).
- The sync differential's oracle follows the model [checked: notes/test-properties.md, `differential::histories_hold_their_closure` reads held-model `spec_closure`].
- **Briefs**: (1c) items 1 to 7, replacing the named-unit reading's stores and oracle; (2) item 8.
- **Unblocks**: B1 (after 1c passes), B2.

### M2. Model: the write path's second round
roles-model `paths` holds the first round [checked: core/test/roles-model/README.md, Paths: 400,000 random worlds and the small family, no failing check under the fixed rules].
- **Briefs**: (1) S3's rules under today's walk (above); (2) the two rules argued and not modelled: what no list keeps, the last-admin rule relying on a named remaining admin with a reader holding one unit's evidence; nobody vouching for its own signer; a re-granted writer's later addendum; (3) what the first round leaves out and A1 builds: descent and dependent things, `until`, invites, finalizes, self-removal by path end, purge authors, own covers and forgetting; (4) the removal's units: logged where the signer could write, absent where it could only read, a holder raised to write after the removal, a promotion while it is on its way; (5) public and external grants (notes/write-path-design.md §6).
- **Checked by**: `cargo run --bin roles-model -- N paths` through `tools/heavy`, each new rule with its negative control.
- **Unblocks**: S3 (brief 1), A1 (2, 3), A3 (4), A5 (5).

### M3. Model: evidence completeness
held-model: a reader holding only a unit, its required set computed from its own holdings, judges every write of the unit as a node holding everything does; a removal's copy with its reach is judged required; evidence leaves with the commit that needed it (notes/write-path-design.md §6). One brief, after M1 and M2 brief 3. **Unblocks**: A2.

### B1. Holder things in steps, handle and key blobs, homes, the walk
Additive: things still ride under enclosing sync IDs, and a node keeping a root unread also walks to members.
- **Changes**: spec/sync-ids.md §3 (claims by sync-role key for every holder thing with a direct grant, entry boxes for them, the superseded sync secret in a step), spec/wire.md §4 (a strong's home beside the value in a delta, carried on by snapshots), §5 (the handle class and the key class), §7, §8; spec/sync-judgement.md §2 (both classes in the required set, judged at the end of a complete pass, standing under a dispute while either side asks); engine writing (filling the home), `sync/set.rs`, `sync/units.rs` (a unit kept unread has out-edges; a unit entered where a handle and a key for it are in entered units and its step lists a thing whose secret is held); osis-sync `unread`, `store` (the index of key tags). spec/requirements.md Data a node cannot read and Data model: the wording of issues/unit-keeper-learns.md and issues/unit-reference-home.md, for Tess to see with the spec brief.
- **Briefs**: (1) spec and wire; (2) steps: claims and entry boxes for holder things; (3) homes: delta metadata, filled at writing, kept by snapshots; (4) handle blobs and key blobs: logged and deleted by any writer from the unit alone (notes/sync-unit-design.md §2); (5) the walk over them for a unit kept unread, dropping, caps; (6) the sim scenarios.
- **Checked by**: rule tests; sim scenarios: a fresh reader served only by a node keeping the closure unread, with a unit reached through a referrer that holds no role on it and whose writers read it alone (the root holds the key), with a grant made after the reference (no write in the referrer's unit), with a strong to a dependent thing of a unit that dropped it, and with a hostile writer's forged and deleted blobs set right by one honest writer of that unit; the differential unchanged; counts at n and 10n members: blobs at a detach (at most two), at a grant (one, in the grantee's unit), and at a removal from the root (none per member).
- **Depends on**: M1 brief 1c. **Unblocks**: B2.

### A1. Stated paths and the purge author
Accounts unchanged: today's account key is the signer.
- **Changes**: spec/wire.md §4 (`signer` and `path` replace `author` and `actor`; the hashed path per thing; the purge-author index), spec/commits.md §1 and §4, spec/permissions.md §5.1 to §5.2 and §6 rewritten along one path (notes/write-path-design.md §1), spec/crypto.md §7 (level 2 is the purge author's); osis-commit, osis-perm (validity as a point query per hop, the hop index, `first_held` per path; `roles_on` stays for keys and `holders`), engine apply and writing (the session's default path), `osis` (`Write::act_as` states a path and purge author [checked: core/osis/src/write.rs]), CLI. Certificates certify the stated path.
- **Lands here from S3's list**: what no list keeps (an entry naming a lowering of an edge the listing write's own stated path rests on is read as absent; M2 brief 2 is to model it), the last-admin rule judged alike (a named remaining admin), nobody vouching for its own signer.
- **Removes**: the header's `actor`; the Acting check; "losing a path while another keeps the class is no fall"; the reachability search of an audit (`audit_fall`, the forward roles cache [assumed: names from notes/write-path-design.md §1, osis-perm]); the certificate search over any path.
- **Briefs**: (1) spec; (2) header and commit crate; (3) osis-perm walk by path, against `paths` as its differential; (4) purge author and delete keys; (5) engine writing and the default path, `osis`, CLI; (6) the last-admin rule; (7) counting: perm work per write at n and 10n (issues/perm-eval-cost.md).
- **Checked by**: an osis-perm differential against roles-model `paths` replacing those against `joint` and `edges`; `held_set_decides` with held-model updated in brief 1's wake; gate.
- **Depends on**: M2 briefs 2 and 3. **Unblocks**: A2.

### B2. The switch
- **Changes**: spec/sync-set.md §2 to §3 and spec/sync-judgement.md §1 to §2 rewritten to the unit (an independent thing and the dependents it reaches inside the unit; spec/sync-set.md §3 A thing leaving a sync unit kept for those, on one sync ID); spec/permissions.md §4 Role changes travel reduced to the holder's own unit; `bodies_under` and `sync_bodies` per unit; the promotion move and the delete-after-carrier rule (notes/sync-unit-design.md §5); the one walk of §3 for readers, over the same blobs.
- **Removes**, in the same stage (no half state is specified): spec/sync-judgement.md §1 Retag across units and Per-sync-ID copies for bodies, "T's keys open X" as what decides carriage, the chain form of Role changes travel; the body-deposit and promotion paths for nesting; `Body::to_sync_id` for parts not derivable; the `keys_open` half of engine `sync/units.rs`; the pull anew of an enclosing sync ID at a new strong [assumed: the code sites of notes/sync-unit-design.md §1].
- **Briefs**: (1) spec; (2) the unit in `units.rs` and the reader walk; (3) bodies per unit, with retag, nesting deposits and body copies deleted; (4) promotion: the move, the carrier rule, the late writer; (5) the differential on the new oracle, its full-size classes run again; (6) sync leftovers closed or re-read (below).
- **Checked by**: the sync differential and sims on M1's oracle; B1's scenario; `tools/gate.sh`; the networking check by hand (notes/testing.md).
- **Depends on**: issues/unit-dependent-release.md for whether the release of dependents inside a unit is kept (proceeding: kept). **Unblocks**: B3, A2. The note for the readable-closure model stays: notes/sync-unit-scope.md, The readable-closure model.

### B3. Status over a closure
spec/sync-status.md, osis-sync `status`, the `osis` wait over a closure (notes/api-design.md), CLI and app where they show sync state. One or two briefs. Checked by rule tests of the fixpoint (a pass of one unit adding members) and the sims.

### A2. Evidence per unit
- **Changes**: spec/permissions.md §4 and spec/sync-judgement.md §1 to §2: a unit's evidence is the closure over the paths its held commits state (notes/write-path-design.md §2), logged with the commit that needs it and leaving with it; a holder's taken grants in the holder's unit; pending on missing evidence; deposits promoted once their evidence is under the unit. Engine `sync/certified.rs`, `sync_ids/certs.rs`, `sync/certblobs.rs` rebuilt as the one derivation [checked: the three files exist, 1059, 711 and 514 lines].
- **Removes**: chain certificates over any path, "closed under authors", each path thing's `keys.0` as evidence, the duty to log one's account's chain on first logging under a sync ID. The account's rotations as header-only copies and its thing lists stay until A4, as the evidence of today's signer.
- **Briefs**: (1) spec; (2) the derivation and its required-set rule; (3) logging and leaving, copies; (4) taken grants and Bootstrap; (5) sim and differential: a reader holding one unit judges as a node holding all.
- **Checked by**: M3's property in `held_set_decides`' held-model comparison and the sync differential; stored bytes per unit counted against notes/sync-unit-design.md §8's "half the entries are certificate copies".
- **Depends on**: nothing open (the read secret stays out of steps). **Unblocks**: A3. Closes issues/certificate-copy-never-shrinks.md; issues/cert-blob-hostile-delete.md is re-read.

### A3. A removal's list and where it is logged
- **Changes**: spec/permissions.md §5.1 Frontier: a leaf per thing and an entry per role commit in the list tree (the built tree of §5.5 moves to the ordinary removal [checked: core/commit/src/lists.rs, core/engine/src/flows/lists.rs exist]); the copy of a removal under a unit with its leaves, entries and reach; logged under every unit where the signer could write, invite or make an enabled reader-level act, for good; the standing duty and the debt; holding a unit for the errand of logging there (notes/account-membership-design.md §4; notes/sync-unit-design.md §12 cases 2, 3, 6). No hear-out operation: core removes when told (Tess); what a retiring node still holds reaches the others by ordinary sync, waited for by the general wait on connected nodes.
- **Removes**: the one frontier over every thing and its bound on a removal's size.
- **Briefs**: (1) spec; (2) the list tree in the ordinary removal, perm and engine; (3) the copy per unit and its required-set rule; (4) finding the units, the duty, the debt; (5) counting: a removal over n and 10n units (entries, stamps, store rows).
- **Checked by**: M2 brief 4's properties through the osis-perm differential; a sim scenario: a stolen node's first write in a unit it never wrote is invalid at a reader served only by a node keeping the unit unread; gate.
- **Depends on**: nothing open. **Unblocks**: A4.

### A4. Accounts as ordinary things
The flag day of (a): an account is an independent thing A, its members signers, a key per node per account.
- **Changes**: spec/permissions.md, spec/crypto.md §3, spec/wire.md §4, spec/sync-set.md §1, spec/sync-inbox.md §1, spec/sync-opens.md §2 (a proof of a signer); engine: making an account mints A with the first signer, pairing is a grant with a step and the pairer's trust entries, removing a node is the ordinary removal, a thing minted with A is its dependent; the `osis` account calls keep their names over the new mechanism (they move at A6); CLI and app follow.
- **Removes**: spec/permissions.md §5.4 Signing chain and §5.5 Account epochs, spec/crypto.md §9, the header's `epoch`, `rotation`, `reseal` and the inner signature [checked: spec/wire.md §4 fields 14 to 16, Inner signature]; engine `flows/account.rs`, `flows/custody.rs`, `flows/lists.rs`, `flows/signing.rs`, `sides.rs` (account sides) [checked: files exist, 1450, 271, 231, 790, 308 lines]; osis-perm `epochs.rs`, `chain.rs` [checked: core/perm/src]; core/keys `account.rs` [checked exists; assumed removable]; roles-model `custody` and `epochs`, the custody differential (`rotation::tests_custody`), core/test/tla/rotation Account.tla with its `Acc_*.cfg` [checked: exist]; the account root; "a thing minted with an account as admin is independent at birth"; the account evidence A2 kept.
- **Kept on purpose**: notes/account-membership-design.md §7, Node anonymity as it was built (Tess); it stops saying "while they stand" of the spec sections once they go.
- **Briefs** (a rewrite of an area: notes/coordination.md, Rewriting an area. Every branch still lands on main, notes/coordination.md One base branch: the new account modules are built beside the old ones, unused, each a branch of its own with its tests; one last brief switches account creation, pairing and removal over and deletes the old machinery in the same commit, so main never holds half an account system in use): (1) spec; (2) signers: keys per node per account, steps listing them; (3) making an account and its things as dependents; (4) pairing; (5) removing a node, with the stolen-node walk of notes/account-membership-design.md §2 as tests; (6) the deletions in engine and perm; (7) `osis`, CLI, app adapted; (8) models and differentials: custody and epochs removed, the membership instances of M2 as the perm differential, sims' worlds rebuilt; (9) counting: a commit's bytes (no epoch, no inner signature), pairing and removal at n and 10n nodes.
- **Checked by**: the osis-perm differential against `paths` with the membership instances; the rotation and deep-departure properties on accounts as holders; sync differential and sims with accounts as units; `-p osis`, CLI and app tests; gate; the networking check.
- **Unblocks**: A5, A6; zero-growth's durable counters per signer; recovery (a recovery key is a member signer).

### A5. Public things, cards, externally grantable
- **Changes**: the public key thing and its five special cases (notes/write-path-design.md §3), a public target's handle and its key from the strong's own delta (notes/sync-unit-design.md §12, case 4), anyone entering by public's static entry; the card aspect and the admin-only aspect naming a thing's inbox and cards, in place of the inbox field of `keys.0`; externally grantable as one switch with tickets; what a thing takes; the granter's refusal; KEM keys published only by a holder or an enabled thing (notes/thing-cost.md, Fewer KEM keys held). spec/crypto.md §3, spec/permissions.md §2 to §4, spec/sync-inbox.md, spec/sync-ids.md §3, spec/data-model.md §9; engine, sync, `osis` (enable, place a card, the public thing's tid), CLI.
- **Removes**: the inbox field of `keys.0` and `Engine::inbox_thing`'s rule; KEM keys of things nobody seals to; the profile and card travelling as certificates.
- **Briefs**: (1) spec; (2) the public key thing in perm and keys; (3) public units in sync; (4) cards and the inbox aspect; (5) taken grants and the refusal; (6) keys following the switch, counted per independent thing.
- **Checked by**: M2 brief 5 through the perm differential; sims: a profile fetched by a reader served only by a node keeping the referrer unread; a stranger's sealed fire reaching a unit kept unread and promoted; bytes per independent thing against notes/thing-cost.md's 14.9 KB.
- **Depends on**: nothing open. **Unblocks**: A6; the two leaks of priorities item 3 are judged again here.

### A6. Core without accounts
- **Changes**: a library crate beside the first-party schema takes `Osis::pair`, `Joining`, `pair_offer`, `pair_accept`, `me`, `account_root`, `nodes`, `remove_node`, `profile`, `profile_of`, `contact_card`, `import_contact` and the account-making half of `Osis::create` [checked: these exist in core/osis/src/account.rs, share.rs, handle.rs]; core keeps signers, a session's default path and purge author, and the dial aspect (notes/write-path-design.md §5 table). The schema describes a realm, a home and an account (notes/realms.md, issues/realms-design.md); profiles are public things, the dial list a contact-only thing. CLI `me`, `pair`, `contact` call the library; app and libs/kit follow (notes/app.md).
- **Removes**: the account calls from the `osis` crate; the sibling rule of dialing; "the account's inbox" as core's.
- **Briefs**: (1) the `osis` surface (notes/api-design.md); (2) the library crate; (3) schema: realm, home, account, profile, contacts; (4) dialing by the dial aspect; (5) CLI; (6) kit and app.
- **Depends on**: nothing open. **Unblocks**: realms' UX work; schema discovery and templates stay parked.

### Z. Clean-up
The renames left (below); notes/terms.md, Built and being moved to, reduced to what is true; issues closed or re-read; the TLA vocabulary pass with a TLC rerun; notes/overview.md and notes/architecture.md brought to the result.

## What is deleted, and when
| what | stage | must exist first |
|---|---|---|
| Retag, nesting deposits and their promotion, per-sync-ID body copies, "T's keys open X" deciding carriage | B2 | handle and key blobs and the walk over them (B1), M1 |
| Chain certificates over any path, certificate placement by what a sync ID's thing may read | A2 | stated paths (A1), the unit (B2), M3 |
| The header's `actor`, the Acting check, the audit's reachability search | A1 | M2 briefs 2 and 3 |
| The one frontier over every thing | A3 | evidence per unit (A2) |
| Signing chain, epochs, custody, merges, account sides, thing lists and listings; `flows/account.rs`, `custody.rs`, `lists.rs`, `signing.rs`, `sides.rs`; perm `epochs.rs`, `chain.rs`; the header's `epoch`, `rotation`, `reseal`, inner signature | A4 | the ordinary removal complete (S3, A3) |
| roles-model `custody` and `epochs`, the custody differential, TLA Account | A4 | `paths` holding the membership instances (M2) |
| The account root | A4 | A as a unit with dependents |
| The inbox field of `keys.0`, KEM keys nobody seals to | A5 | cards |
| Account functions in the `osis` crate | A6 | public profiles and cards (A5) |

Kept as records (Tess): node anonymity as built, notes/account-membership-design.md §7; the readable-closure model, notes/sync-unit-scope.md.

## What the other priorities do meanwhile
By item of notes/priorities.md.
- **First, main's failing properties**: proceed first (G).
- **2. Whole commits tail**: invalid bodies kept at stores stays a Tess call and proceeds; "re-grants restoring from stores" matters more after S3, since a vouch arriving late fetches bodies again. Drop-rejoin's holder-logs-again waits for B2 (it logs under one unit then). Zero-growth: the tombstone design that needs a stable writer waits for A4 (each signer is one); its other rows proceed.
- **3. Key passing and grants without history**: history-less-grant's next step (records of dependent things under another's sync ID) is overtaken by B2. removed-device-reads-later-grants is judged after A4, fresh-deposit-seed-readable-by-departed after A5.
- **4. Bounded memory tail**: proceeds; it touches neither redesign.
- **5. Account signing tail**: overtaken at A4; account-signing, account-side-shared, rotation-names-grow close there, maker-unknown-from-snapshot is re-read [assumed].
- **6. Slimmer things** (notes/thing-cost.md, Ranked candidates):
  - Free by a redesign: 4 (no `epoch`, no inner signature: A4); the KEM keys most independent things publish (A5); `X/` only for a blob under several sync IDs (12, mostly free at B2).
  - Moot: `actor` absent when equal to `author` (14: A1 replaces both); the account root's ticket in the making commit (Rejected there: the root goes at A4).
  - Wait: 1 (store each commit once) until B2 removes body copies; 3 and 13 (the echo, the blob ID beside an inline blob) until S1 and B2 settle the entry flow; 5, 6, 8 and the delete-key ideas (wire format of a commit) are done in one pass after A1's header change, so the header changes once more, not three times.
  - Proceed any time: 2, 7, 9, 10, 11 (engine rows).
  - perm-eval-cost: counted in A1; many-sync-ids-cost: S1; many-things-cost, derived-state-recomputed, chat-add-cost proceed.
- **7. Sync leftovers**: closed by B2 without a fix: refetch-ticket-test, the retag items of sync-unbuilt and sync-tests-owed, the `rewrap` item of sync-pending-leftovers; run again after B2: differential-full-size-classes; re-read after B2: sync-parks-check and sync-tests-owed (deposit items), storage-owners, sync-models-lag; closed or re-read at A2: certificate-copy-never-shrinks, cert-blob-hostile-delete; wait for A5 and A6: stranger-fire-bounds, dial-candidates, sync-link-first-contact; proceed: redeem-leaves-a-blob, forged-ticket-sync-id-entries, cover-before-commit, opens-hit-index-cost, timed-loss-wait.
- **8. Long tail**: proceeds beside; an issue in the perm walk (settled-writers-dispute-script, dispute-scan-cost) is checked against A1 before a fix.
- **Parked on Tess**: unchanged; recovery is designed after A4; settings and client auth do not collide.
- **Renames owed** (issues/deprecated-terms.md): `author` and `actor` in the header at A1; key actor to signer, device for a node, devices, the account root at A4 (they go with what they name); `actor` in identifiers (`mint_actor`, holder actor, client actor) at A6 and Z, each use read; the TLA vocabulary at Z, with Account.tla's share gone at A4; `Placed` when A2 rebuilds `certified.rs`; the spec's rule words (edge, rights, demotion) where A1 rewrites §5, otherwise unscheduled; the reference-graph words stay with their own rebuild.
- **Later designs that build on this**: readers hidden from each other (issues/readers-see-readers.md) after A2; hidden mode stays a design.

## Two stages far larger than the rest
A1 (the permission walk rewritten along stated paths, and a header change that touches every commit made anywhere, the conformance vectors of core/test/vectors and every test fixture) and A4 (the account system replaced). Their briefs above are the first cut: the coordinator splits each further before starting, with the spec and model briefs done and reviewed before any code brief is written. Every other stage is of ordinary size.

## Risks
1. **The path-judged walk with two-walk vouches does not hold up outside the first round's worlds** (descent, `until`, invites, self-removal, own covers; a component holding a vouch walked twice). Cheapest check: M2 briefs 2 and 3, before any A1 code; then A1 brief 7's count at n and 10n.
2. **Promotion under the switch** (a promotion judged invalid, forked promotions, a late writer, a removal on its way) loses or strands bodies. Cheapest check: M1 brief 2, every arrival order, before B1 is built.
3. **A removal's units**: the cost at an organization's scale, and the raised holder (a signer removed while its account only read a unit, the account raised to write later). Cheapest checks: M2 brief 4; reading spec/crypto.md §4 Floors for whether readers take content sealed under a superseded epoch; A3 brief 5's count. If the raised holder is a real window, the removal is also logged at the raise, by the duty already stated.
4. **Many sync IDs stay costly per unit** after S1, which would make a closure of units slower than the bag it replaces. Cheapest check: S1 itself, first, counted at n and 10n; B1 is not started until S1's counts are flat.
5. **Two rules are argued, not modelled** (what no list keeps; the last-admin rule's named admin). Cheapest check: M2 brief 2, two hand worlds each with its negative control.
6. **The join fails over time what it holds statically.** Modelled: stores judged after a complete pass, writers with different holdings, forks and a hostile writer hold; four statements fail (notes/closure-model.md, Findings against the design: a dependent holder a keeper cannot use, a key too many opening by its credential, two on homes). What the model lacks (dropped holdings, deposits, disputes beyond two sides) is listed there.
7. **A handle blob per referenced thing costs too much where one unit references very many dependents of another** (about 400 B stored per reference per node). Cheapest check: B1's count at n and 10n; the way out is the API steering to independent targets, not a second kind of blob.
8. **Homes meet the CRDT badly** (a home must live exactly as long as the strong its delta wrote, through covers, snapshots and held history). Cheapest check: B1 brief 1 states the rule in spec/wire.md and spec/crdt.md terms before brief 3; if it cannot be stated in a few lines, the home moves into the reference value and issues/unit-reference-home.md says what an app then observes.

## Not established
- Whether readers reject content sealed under a superseded read epoch (risk 3).
- That a pass holding a unit for an errand fetches no linked chunk, tree or page blob [assumed].
- Which TLA rotation models hold the withdraw rule S3 brief 4 changes.
- The cost defects' causes (S1 briefs 1 and 3 start by finding them).
- That all five full-size differential seeds are multi-unit carriage (run again after B2).
- Bytes of a removal's copy per unit, and of an evidence set per unit: counted in A2 and A3, not computed here.

# Stub rewrite
> Summary: The rewrite replacing key parts (grant copies kept under the holder's sync ID) with reference-driven stubs, per Tess's model; go-ahead from Tess, details open to her revision. Target design, working answers to its questions, what is deleted, the jobs and their state. Rules land in the spec; this note holds the plan and what the rewrite still owes.

## Status
Tess approved building this shape, taking the recommendations below as working answers (Q1–Q6); she may revise details. Aim for a general shape that works and fits the principles before nailing details. Special cases the general rules make needless are removed as met.

| Job | State |
|---|---|
| M1 held-model | done (Model findings) |
| R1 delete | landed |
| M2 TLA | done (Model findings M2); Q1/Q2 answer changed: notice form, for Tess |
| R2 stubs | landed; what it owes and the choices it made: R2 built, below |
| R3 entry, R4 tests/notes | not started; placeholders owed below |


## 0. In short
- Delete key parts' edge pieces and everything built to deliver, read or found entry on them. That includes every rule whose job is to make sure a holder hears of a grant.
- In their place:
  - A unit carries what it references, whole or as a stub. X's stub is X's role entries, cut to what the unit's readers open.
  - The unit also carries the stubs of the holders on its chains.
  - Stubs are logged by nodes that hold them and follow X's own sync ID.
- Telling a holder is optional: a signal whose value names X and how to reach it. The receiver then follows signal → reference → sync from X's own sync ID.
- No signal carries commits or parts.
- A grant nobody is told of is a valid state. Nothing tries to prevent or repair it.
- Order: models, then four rewrite jobs on main, then one review and one gate.

## 1. "Logging" in these terms
- A node **logs** something under sync ID S when it writes it into its own store as an entry of S.
  - It stamps the entry if it may write S, and deposits it otherwise.
- Peers syncing S then pull the entry from it.
- That is the only way anything is "carried" by S.
  - Only a node that syncs S and holds the data can log it.
  - What no such node has logged is not under S, whatever the rules say S should carry.
- "X's stub is in U" therefore means: some node reading U, holding X's role entries, logged their cut under U's sync ID.

## 2. Target design
**Principle:** a grant is the granted thing's own data. A node syncs what its references reach. A stub is the referenced thing's role entries, cut to what the carrying unit's readers can open. Nothing is kept with a holder or sent to it for having been granted something.

1. **Stub.** X's role entries, cut to the readers of unit U:
   - X's `secrets.0` pieces boxing the holders on U's chains to X;
   - the public's open boxes;
   - the rest piece, where they read;
   - the edge writes of those edges, `sync.0`, and evidence.

   Readers that reach X only at sync get the sync-only cut (no header, no evidence: the requirements line on what a sync holder learns). Carrying X whole includes its stub. So "U's keys open X" is always judged from what U carries of X. That one rule replaces public pieces and a unit's own grant pieces.
2. **What a unit carries** (rule 2). U is a thing's unit, or the node's local part.
   - A strong to X that U's keys open brings X whole.
   - A weak to such an X brings its stub.
   - A reference to an X that U's keys do not open, where U's thing holds sync or above on X, brings X's stub.
   - Otherwise nothing is carried.
   - Every holder on a chain by which U's keys open something U carries is a stub in U.
   - Carriers (replacing rule 2's edge-piece sentence): a stub is under U's sync ID only as a node reading U logs it from X's role entries it holds (§1). That node usually wrote the reference.
   - With no such node there is no stub: a bare reference, irregular, given no support (the NotCarried warning).
3. **Kept current.**
   - A stub's holders follow X's own sync ID for role entries alone. This is today's "keys" source class, renamed.
   - They log each new cut under U.
   - A rotation reaches them wrapped under the epoch it supersedes, which they already hold.
4. **First entry:** by a unit carrying X, or by a held signal's weak reference (rule 4) once its fetch (point 6) has given the stub. A node's role is X's grants as it holds them, through the stubs of the holders on its chains.
5. **Grants need not reach holders.**
   - Core writes the grant on X and nothing more.
   - Whether anyone sends a signal is the API's or app's choice (the `osis` API may do it by default).
   - A holder with no signal and no reference to X holds nothing of X. That is correct.
   - Removals likewise: stub holders see a removal in X's role entries. Others need nothing.
6. **A grant signal carries values only:**
   - a weak reference to X (its tid);
   - X's sync ID;
   - an entry credential;
   - peer hints (addresses, as a link's `peer`).

   The receiver: the weak reference holds X's stub (rule 4). It opens X's sync ID by the entry credential and takes the entry box. With the secrets that box gives, it reads X's role entries from X's own sync ID and judges its grant by X's record (the tid certifies it) and X's role commits. That fetched cut is the stub. Q1 explains why the entry credential is needed.
7. **Public things.** Covered by the stub (point 1). The public entry in X's own steps stays.
8. **Second node of an account.** Pairing hands over A's values by hand (the same fields as a signal). The node strongs A from its root, syncs A, and A's unit carries everything A references, whole or as stubs, with the chain-holder stubs. A's inbox is a thing A references (rule 5), so held signals come with it.
9. **Local part.** The node root's references keep their stubs in the node's own store. This replaces the record-edge piece.
10. **Departed members** (Q6) and holders that cannot open a re-seal or sync rotation by its wrap (Q2): both through X's own sync ID, never the holder's.

## 3. Questions (working answer: each recommendation; Tess may revise)
**Q1. What a grant signal's value must hold, and how the receiver gets in.**
What I found (read):
- Everything under X's sync ID is wrapped under X's secrets, so a node holding none reads nothing there.
- The receiver's box is inside X's role commit, under that wrap.
- Opening X's sync ID needs proof both ways (spec/sync-opens.md §4):
  - the receiver can show a secret, a claim of a step it knows (it knows none), a static entry, or the public entry;
  - it can judge the serving peer only by X's roster (it holds none) or by that peer's proof.
- X's tid certifies X's record, but X's sync ID is X's own only by a step bearing the sync key of a secret the node holds (§4 Owner).

So tid + sync ID + addresses are not enough: the node can neither open the sync ID nor find its box. Links already solve this exact problem: a link key's **static entry** in X's step claim set, with an entry box (spec/sync-ids.md §3, wire §8). The redeemer opens by the entry and takes the box.

Options:
- (a) **A grant entry, as a link's** [recommend].
  - The granter adds a fresh entry for this grant to X's claim set. Its entry box is sealed to H's read KEM key, so the entry alone gives no secret.
  - The signal's value carries the entry's signing seed (a value: bytes).
  - Signal → weak reference → open X's sync ID by the entry → box → role entries → stub.
  - One mechanism with links and the public entry.
  - Cost: one sealed entry box per signalled grant, in each step while the entry stands (the claim set already lists every reader).
  - Sub-question: does the entry stand while the grant does, or for the signal's lifetime? Recommend the signal's lifetime, since after that nothing holds the value.
- (b) Every holder gets an entry box in every step, and the value carries the current step's public key. Stale after the next step; boxes for every holder at every step.
- (c) Keep a commit copy in the value (today's offer). Ruled out by Tess's correction.
- Every option has a remaining gap: a value naming a forged sync ID wastes a fetch but gives nothing. The entry box must open and its sync secret must derive the head's key.

**Q2. Holders that cannot open a re-seal or sync rotation by its wrap** (a holder left out of a rotation, then re-sealed; a sync-only holder's new sync secret). Today these go as sealed copies under H's sync ID (a kept list on the holder: delete). Options:
- (a) An entry box for that holder in X's next step, the Q1 mechanism [recommend].
- (b) Notice-form entries under X's sync ID sealed to the holder.
- Risk for both: a store whose head moves to a step past its keys before it takes the box stops (sync-judgement §6). M2 models this.

**Q3. Weak references bring stubs, and each stub is followed.** That is one followed sync ID per distinct weakly referenced independent thing (for example, one per author profile in a chat).
- (a) As decided [recommend], with an n/10n counting test.
- (b) A weak's stub is carried but not followed.

**Q4. Drop keys-open travel** (finding 19). Stubs on the chain carry a hop's removal to everyone reading or writing through it. What is left: a reader of R by its own grant may accept a stolen key's write until the removal reaches it, which the requirement "removal binds honest nodes that receive them" allows. Recommend drop, with the gap measured in M1.

**Q5. Drop following by the public entry.** A unit that lost its role on X learns that X turned public only once a node syncing both logs X's stub. Recommend drop.

**Q6. Telling a departed member.** Notices are X's own data, under X's sync ID, and serve the erasure property (a node that lost access keeps nothing it can no longer read).
- (a) Keep notices as the one form [recommend].
- (b) Serve the departed member only X's role entries up to its departure. Fails where those are wrapped under epochs it lacks.

## 4. Drift to delete: rules that make sure holders learn of grants
- permissions §4 Delivering an edge piece (all of it); Key part's edge pieces; Role changes travel's key-part half.
- sync-inbox §5:
  - "a node writing an edge write naming H where it may not write H ... fires `grant@~0`" (a mandatory fire);
  - "a removal from outside goes as a grant does";
  - "a grant by a node that may write H needs no fire: it is logged under H's sync ID";
  - "Carried commits ... in H's key part".

  Keep the signal itself as an optional value-level signal (§2.6).
- sync-inbox §2 Sealed copy (delivery to the holder's sync ID).
- Code:
  - `flows::inbox` `deliver_copy`, `deliver_with_steps` and the `sync_sent` rows, `deliver_step`, `deliver_sealed`, `fire_copy`, `unowe_grant`;
  - `flows/edges.rs`'s calls to them;
  - `rotation/mod.rs` `deliver_rotation` and the re-seal delivery.
- API: the `Osis::grant` doc ("reaches that thing's readers through it ... waiting until then"). A signal becomes an option of `grant`.
- notes: node-closure "Learning a grant", "Kept: a grant naming a holder in the holder's key part"; sync-inbox.md "A removal reaches the removed holder as a grant does"; write-path-design §231 "a writer of A delivers a grant to it".

## 5. Realms
- A realm is a thing with the realm marker. Its holders and its references have the consequences the general rules give; nothing is realm-specific.
- Minting with a realm as admin is a grant (the record edge), which a node cannot necessarily find. `holds.0` is a set of references.
- **realms.md becomes:**
  - the marker and its fields;
  - "members are its holders" (R's own roster);
  - that every combination of grants and references behaves by the general rules;
  - UX notes.
- **Delete from realms.md:**
  - "In the realm is every thing R is mint admin of or holds a grant on";
  - "Contents listing needs ... what does thing X hold a grant on";
  - "The contents list is R's grants" and "Removing a document's strong from R does not revoke its grant" (it is the general rule: say it once in the spec);
  - the property table rows that rest on "in the realm";
  - "Things created in a realm".
- What an app shows as a realm's contents is what it references: the app's choice.
- **osis-account `Realm`** (read: `at`, `make`, `thing`, `profile`, `contact_card`, `profile_of`) has no grant-based contents API. Keep it: `make` (minted with `within`, referenced from `within`) is one convenient arrangement. It gains nothing. Drop any doc wording that defines what is "in" a realm.

## 6. Special cases the rewrite removes (the general rules cover them)
- A thing as its own inbox (rule 5: the inbox is always a thing of its own).
- Public pieces, and following by the public entry (the stub covers them).
- Three ways to hold a thing without content: held for keys, a stub, and sync copies in key parts. These become one: the stub (sync-only cut where needed). Kept unread stays only as "synced at sync role".
- The record-edge piece in the mint admin's key part, and sync-ids §2's newly-independent clause: references cover these.
- The "may write H" branch of grant delivery.
- Sealed copies of steps to sync-only holders, and of re-seals: one entry mechanism with links and the public (Q2).
- sync-set §2 Making a thing's clause for things holding only role entries ("held as any holder of what the node syncs"): a chain stub or a reference covers it (re-check link keys, which joiners reference by strongs).
- sync-set §2 Own things' long list of where grants count: becomes "where the node holds them, whole or as a stub".
- crypto §3 KEM keys "for keys": a keyset carries its KEM key wherever the thing holds a role on anything (it can be boxed).
- realms' "in the realm" (§5).
- The fire value as an `EdgePiece` shared with pairing: becomes one value-level form for signals and by-hand pairing.

## 7. How the rewrite is done (Tess's constraints)
- **One home per fact.** Each rule is stated once in the spec. Notes point to it and never restate it. The review rejects duplicates.
- **Every spec rule traces to the model or a principle.** No rule invented for one case; one that cannot be traced goes or becomes a question.
- **Delete before building.** R1 removes the old concepts completely, from spec, code, tests, notes and comments. A remnant grep at review must come back clean: `edge piece`, `key part` (in its edge-piece sense), `public piece`, `held for keys`, `follows_public`, `by_public`, `deliver_copy`, `keys-open travel`, `sync alone` as a separate concept.
- **Terms.** Every term the new spec uses (stub, carry, log, entry credential, stub class) is defined in notes/terms.md. Every deleted one goes in issues/deprecated-terms.md.
- Model first. One branch's worth of work on main. Main may be broken from R1 to R4. One review and gate at the end.

## 8. Model work (first; every property paired with controls that fail)
**M1, held-model:**
- `closure::entry` rewritten: carriers are references in units, the local part, and held signals whose fetch succeeded. Chain-holder stubs. No key parts, following or public pieces.
- Properties to check:
  - Founded
  - Agreement between readers
  - No grant-driven fetch (a node with no reference and no signal holds nothing of X, whatever its roles)
  - Siblings
  - Chains (against the old `on_paths` oracle)
  - Signal lifetime
- `closure::keys` and the public models fold into it.
- `evidence` without keys-open travel or `key_part_whole`. The joint property rerun with chain stubs. Finding 19's gap reported for Q4.
- `box_cut`/`copy_cut` as stub cuts.
- The Dependent-entry oracle gap (differential seed 102).

**M2, TLA (in parallel):**
- Q1(a)/Q2(a) entry boxes against a store stopping at a step past its keys. Checks: no current holder stops for good; a signalled holder opens X.
- KemKeys.tla (it delivers by edge piece) and Depth0.tla `pl`/`kpl` (guess: key-part-like) rechecked.
- roles-model `told.rs` (notices) kept or re-pointed per Q6.

### Model findings (M1)
What held-model checks (core/test/held-model/README.md):
- `closure::entry`: units (things' and local parts) carry by rule 2, judged from their own data, only what a node holding the role entries logged; held signals give stubs; chain-holder stubs. Each property fails under its control: founded (`Fix::Greatest`), readers agree (`reader_view`), no grant-driven entry (`by_grants`, the key-part rule), siblings (`PRIVATE`: fetched stubs kept at the node), chains against `on_paths` (`Chains::Up`, the walk up), signal lifetime (`keep_fetched`). Hand worlds: pairing, unsignalled grant, signal then reference then expiry, signal alone, weak, two-hop chain and its removal, public thing, reference at sync.
- `evidence`: a sync ID's required set is its bodies plus its chain stubs' role entries (edge writes on chains of read edges and records from its thing to a thing of its unit), closed over evidence; no delivery to a holder's sync ID. The joint property holds with the actor holding its paths' stubs (each control fails).
- `box_cut`, `copy_cut`, `independent`: the same cuts, read as X's stub in the unit of T (the holder on its chain).

Findings:
- **Q4 gap (finding 19).** A removal of a hop O→D on a chain to R reaches R's readers only where an honest node holding the removal syncs a unit whose chain to a thing it carries passes the hop, and some node syncing that unit also syncs R. Where R is written through the hop only from a local part (or a unit nobody honest shares), R's reader shows the stolen key's write valid until the removal reaches a node syncing R (`spec_reach::reach_a_chain_stub_carries_a_removal_to_the_units_reading_through_it`). The generated evidence worlds reach no case where chain stubs, keys-open travel and bodies alone differ (105 of 1,848 property worlds with a gap under each; `reach_explore`: 20 family worlds): only the hand worlds tell them apart.
- **Signals need the holder opened.** A signal's entry box is sealed to its holder, so a node uses it only where it opens the holder (reads it, or a unit's keys open it). A signal naming a realm reaches a member's node only once it reads through the realm.
- **A reference founds nothing alone.** A strong to a thing (a public one included) is carried only once a node holding its role entries logs the stub; the node writing it normally does. A stub logged under a unit outlives its logger while rule 2 carries it.
- The actor's own reading still matters: `Joint::WorldPaths` fails in generated worlds, though a stub carries a lowering with the hop it undoes.
- Not modelled: bridges (a dependent of another independent thing counts as that thing), rotation and re-seals (Q2), notices (Q6), the Dependent-entry oracle gap.

### Model findings (M2)
What TLA checks (core/test/tla/rotation/README.md, `Entry.tla`, `run.sh entry`): one thing X, an admin, a granter that is no admin, readers and sync-only holders; rotations, removals, holders granted beside the admin's knowledge (left out until it learns them), signalled grants entering late, signals expiring, claim sets dropped, sync-only stores stopping at a step past their keys. Properties, each with a failing control: `Live` (a current holder that entered holds the current epoch for good, a sync-only store back at the head), `SigLive` (a signal standing for good brings its holder in), `NoGain` (a removed holder holds no epoch from its removal on), `NothingKept` (nothing under the holder), `StepsBare` (a step carries no per-holder box, so a store keeping X unread counts no holders or grants).

Findings:
- **Q2(a) as written fails.** A reader stopped at a step past its keys knows only that step (Behind moves one sync key past its credentials) and holds no credential of it, so a claim-keyed box in a later step is never found (`EN_left_next`). The same strands an ordinary reader whose claim set at that step was dropped. A box only in the step bearing a new sync key leaves a sync-only holder learned late stopped for good (`EN_sync_next`).
- **Entry boxes can be made live, but they count holders.** They pass when a stranded reader makes its own static entry and sends its public half in its Stranded message, the admin listing it in every step until it lapses, and every step boxes every sync-only holder (`EN_left`, `EN_sync`); a signal's entry must stand in every step while the signal does, and only while its holder is current (`EN_sig_once`, `EN_rem_nojudge`). But each such box is visible in every step to every store keeping X unread (`EN_sig_bare` fails `StepsBare`): the count of sync-only holders, standing signals and stranded requests. That is the leak Tess rejected (notes/sync-opens.md, Credentials as built). Links already leak this way: a step holds one entry box per static entry (spec/wire.md §8), so every store counts X's link keys.
- **What passes everything (`NT_*`): the notice form, served by role (Q2(b), extended to Q1).** Steps carry no per-holder box. A role commit that boxes a holder unable to open its wrap also seals its blob key to that holder, as a notice does: a grant (to its grantee), a re-seal (to the re-sealed holder), a rotation (to each sync-only holder it boxes, and to each holder holding no box at the epoch it is wrapped under, as the rotator knows). The sealed keys are part of the commit, so a store sees only that commit's padded size, which already grows with its boxes. A reader opening X's sync ID toward the holder by its role (ByRole, J judged on X's roster) serves it; the holder opens those commits by its KEM key and the rotations after them by their wraps. Dropped claim sets stop nobody. A control without the rotation's sealing to sync-only holders fails (`NT_sync_next`); one sealing to a removed holder fails `NoGain` (`NT_rem_nojudge`).
- **What that changes in the design:**
  - Q1: the signal carries X's tid, X's sync ID and peer hints, no entry credential: no per-grant entry in X's steps. The receiver opens X's sync ID by role at a reader of X and takes the grant commit sealed to it; it judges nothing of the serving peer (the secrets it opens must derive a step's sync key, spec/sync-ids.md §4 Owner).
  - Spec deltas (R3): ByRole taken from a holder that does not yet hold S (a signal) and from sync holders (J reader or sync holder), not only reader-to-reader (spec/sync-opens.md §4, §5); the stopped store's node opens commits sealed to it from such a member and keeps S again once it holds its head's sync secret (spec/sync-judgement.md §6 Stops); a role commit's sealed blob keys (spec/crypto.md §5, spec/wire.md beside the notice form); a sealed re-seal or sync-only rotation is retained as the role entry it is.
  - Cost: a holder catches up or enters only by meeting a reader (or writer) of X, never a store alone; a holder behind already gets back in only by role (notes/sync-opens.md). One sealed key per such holder per commit.
  - Open for Tess: whether link keys move to the same form (the redeemer proves K by role at a reader) to end the link-count leak, at the price of links redeemable only at readers.
- **KEM keys (`KemKeys.tla`).** The rule "a KEM key where the thing holds a role" judged by what the rotator holds needs the rotator to learn of M's grants, which nothing guarantees now (`KK_untold` fails `Live`: M's readers that entered A elsewhere lose it). The simplest rule that passes: a keyset carries a KEM key also wherever the keyset it supersedes does (`KK_sticky_untold`, `KK_sticky_stale`), for spec/crypto.md §3 Published KEM keys.
- **Depth0 `pl`/`kpl` are not key parts:** they are removals from a holder actor logged under the sync IDs of what it holds a role on, i.e. its chain stub's role entries (rule 2). Kept, renamed in comments; the model logs only the removals of authors of epochs there (logging every role entry multiplies D0_nc3's states past 20× and changes no rule).
- **Rotation.tla's inbox paths** (grant, re-seal and rotation boxes delivered to the holder) are the sealed-to-holder commits served by role; renamed, results unchanged.
- **roles-model `told.rs`** fits Q6 as is: notices are X's entries opened by the departed member's key. Its `Hear` event (role commits heard by another route) reads as A's stub carried in another unit; doc reworded, no change in what it checks.

## 9. Jobs (one agent, one session each)

| Job | What it delivers | Runs |
|---|---|---|
| M1 | held-model rewrite (§8) | parallel with M2 |
| M2 | TLA checks (§8) | parallel with M1 |
| Tess | decides Q1–Q6 | overlapping M1/M2 (M1 needs Q1, Q3, Q4) |
| R1 | deletes: §4's drift, §6's special cases, the inventory's deleted items, spec and code together, their tests, deprecated-terms entries; clean remnant grep | after the models |
| R2 | stubs: spec once (sync-set §2, permissions §4 Copies, data-model §8/§9, sync-inbox §1/§5, sync.md §3, sync-ids, commits §5) and code (references bring stubs, cut, logging, following, entry, role) with tests; terms.md | after R1 |
| R3 | the entry mechanism for signals, re-seals and sync rotations (Q1/Q2), the signal as an option of `grant`, pairing by values, notices per Q6 | after R2 |
| R4 | slim property tests (second node, member with and without a reference, unsignalled grant holds nothing, signal then expiry, weak keeps stub, two-hop chain, public referenced, removal reaching a stub holder, re-sealed holder, departed told); differential on the new model; known failures and ignored tests re-judged; notes pointed at the spec; realms.md (§5); `grant` doc (api-design pass) | after R3 |
| Review + gate | one each, over everything, including the remnant grep | last |

**Risks:**
- R2 is large (`units.rs` and `certs.rs`, about 2,500 lines). If needed, split it by spec section, never by building beside the old.
- Weak stubs add followed sync IDs (Q3).
- The store stopping order (Q2).
- Pairing, chat and app tests that reached a second node through key parts.

**Issues:**
- *Dissolve:* chain-top-unseen-by-sync-holder (drop its tess-call once M1 shows it), public-follow-retest-cost, the second half of holder-key-churn.
- *Change:*
  - roles-apart-from-syncing: its test becomes a chain-stub test.
  - sync-only-reference: re-state under rule 2.
  - account-evidence-per-unit: cut per stub.
  - attach-pulls-unit-anew: `refetch_holders` goes; re-measure.
  - many-sync-ids-cost: add the stub count.
  - storage-owners: rerun its grant and redeem arms.
  - behaviour-depends-on-own-keys: rule 5 settles the inbox half.
  - sync-alone-stated-path-evidence: re-judge.
  - deprecated-terms: add the deleted words.
- *Re-judge only after R4:* every differential-full-size class, the three known_failures seeds, and the ignored sync-rewrite tests naming pieces or offers.

## 10. Other drift seen
- holder-access-study calls edge pieces "a bootstrap for siblings", the explanation the handoff names as wrong.
- sync-hostile line 47 states key-part delivery as a property.
- "Notice" means two things: the grant's notice in the requirements, the removal notice in the spec. Requirements wording for Tess.
- stubs.md rule 6 ("a grant fire carries the data to make the stub") and its "For the spec piece" bullet (the fire carries an `EdgePiece`) contradict Tess's correction 1. Rewrite them to §2.6.
- holder-access-study "The direction" 1 and sync-rewrite-state "For review: One value for an edge piece from outside" reject the bare offer for the reasons Q1 lists. Q1(a) answers them; rewrite both once decided.


## R2 built
Rules: spec/sync-set.md §2 (Stubs, Carriers, Holding a stub, Sync set, Writing, Making a thing, A stub leaving), spec/permissions.md §4 (Stub, A hop's removal, the stub cut in Copies, Logging certificates), spec/sync.md §3 (Stub, Kept for T, Holders by copies), spec/sync-ids.md §2/§4/§6, spec/sync-opens.md §4 (the stub class), spec/sync-judgement.md §2/§6, spec/commits.md §4, spec/wire.md §4. Words: notes/terms.md.

Engine (`sync/units.rs`): a held stub is a vertex `(Ctx::Stub(X), X)` with no out-list, given by `given_by` over every reference (`refs_from`: current strongs and weaks, held history's strongs) through `stubs_by`: a weak's target where the unit's keys open it or the unit holds sync, and the holders on the unit's chains (`chain_holders`: each holder reading X that an owner reads), only where the node holds a read secret and the unit carries no such holder whole (`Closure::carries_whole`). What an edge gives is recorded per edge (`Closure::by`, `gave`), one mechanism for Dependent entry and stubs. `Closure::holds` is the node closure (no stubs); `holds_any` with stubs (retention roots, release, leaving). Sync set: a stub-only thing's sync IDs as `Holding::Stub` (`thing_holdings`). Logging: `Engine::stub_certificates` adds, under each read thing's sync ID, the stubs its unit gives (`Closure::unit_stubs`): opened, each held role commit on X cut by `stub_parts` with evidence and X's public key record; at sync alone, the sync copies for that unit's thing. Writing: role entries on a stub thing are no write outside the node closure (`engine/write.rs`). The local part's owners are the node's own things (`owners`), judged by the same rule.

Choices taken (simpler option; Tess may revise):
- **Strongs enter by the node's role**: a strong to X that the unit carries (keys open, or sync or above) enters X read or kept unread by the secrets the node holds, as the node closure always did; the model gives the node X whole only where a unit's keys open X. Kept: it keeps kept-unread stores and changes no reading a node already has. A reference at sync is kept unread, not a stub.
- **A stub at sync alone** is the sync copies under the carrying unit; the node follows nothing of X for it (a stub vertex needs a read secret).
- **Chain holders carried whole** are no stubs (the model's rule): without it a chain of local dependents made independent re-gave every holder at each rotation (`scale::a_deep_dependent_made_independent_costs_its_depth_per_rotation`).

Owed by R2 (not built):
- Weaks in held history holding stubs (spec/data-model.md §8 Held history, rule 4): `refs::kept` follows strongs alone; R3 with the signal's weak reference.
- The osis-sync differential's oracle on held-model's stub closure: `harness/history.rs` `MODEL_OFF` skips the model at quiet runs, so World tests play; every test calling `history::check` stays ignored (R4).
- A departed stub holder told of its removal (the two-hop chain's U removed from R reaches node 1 only as a departed member: notices, Q6, R3); `stubs::a_two_hop_chain_*` asserts only that nothing written since is read.
- `stubs::a_two_hop_chain_*` still passes with chain stubs given nowhere: node 1 reaches R's role entries another way not yet found. R4: find it, and give the test a control that fails.
- `differential::a_reader_by_the_publics_box_*` (the public's listing role by its box, `Core::public_listed`, ported from `spar-public-listing-role`): reached by a public redeem, they pass with the listing counted whatever its head; the case the branch's test reached (a node holding sync of its own learning the head) needs a signal (R3).

## Owed by R1, for R3/R4
Placeholders left in the spec, each `[Stub rewrite (notes/stub-rewrite.md): ...]`, for R3:
- spec/permissions.md: §3 Re-seal (Q2); §4 the grant signal and its receiver's entry (Q1); §8 Pairing (A's values).
- spec/sync-set.md: First entry (held signal, rule 4).
- spec/sync-inbox.md §5: the grant signal (values, held while the setting keeps it; pairing by hand).
- spec/sync-hostile.md §2: the grant signal; what a holder lacks until it takes its entry box (Q2).
- spec/commits.md §5: what a held grant signal needs.
- spec/data-model.md §9: the `grant@~0` value.

Code sites marked `// Stub rewrite (notes/stub-rewrite.md): ...`, for R3/R4:
- engine `flows/inbox.rs` `take_fire` (a grant signal of values) and `open_fire_in` (a sealed sync copy is no fire: entry boxes, Q2).
- engine `rotation/mod.rs` `recorded`, `reseal_one`, and `flows/sync_ids.rs` `issue_step`: a holder that cannot open a rotation, re-seal or step by its wrap gets an entry box (Q2).
- engine `local_peer.rs` `pair`/`take_pairing`, osis-sync `driver/mod.rs` and `harness/mod.rs`, libs/account `Offering::accept`/`Joining::finish`: pairing hands over A's values. The reply carries nothing now; the new node holds A from its root but has no way to sync it. Pairing also handed over the pairer's trust records (dispute sides on A, `Sides::adopt_trust`, deleted with offers): R3 decides how a new node gets them.
- Tests: engine `apply/tests_validity.rs` (a stub cut covering as the whole snapshot does), `tests/it/scale.rs` (a stub's bytes per node), osis-sync `tests/it/harness/history.rs` (`unoffered`/`pieces`/`named`, the oracle, `MODEL_OFF`).
- Ignored tests carry `#[ignore = "stub rewrite: ..."]` (`tools/ignores.py "stub rewrite: "`): engine 14 (pairing and the signal, R3; removed holders asserted on, which hold nothing under the model; a keyless grant carries nothing; 6 not sorted), osis-sync 137 (entry by references and stubs, pairing by values: most need a signal or pairing to reach another node, or call the oracle), osis-account, osis-chat and osis-app (pairing). R4 re-judges each.

Also owed: `tools/policy.py` `STUB_DEAD_WORDS` refuses the deleted words in spec/, notes/ and issues/ only; widen it to every file once code and core/test/held-model are clean. The notes still describing engine and held-model code being rewritten (notes/closure-model.md, core/test/held-model/README.md) are R4's.

## Appendix 0: inventory tables
(spec/notes rows, then code rows; Q numbers refer to §3 above)

### 1a. Spec and notes: each use, the job it does, and what replaces it
| # | Where (read) | What it is | What users see it do | Replacement under the model |
|---|---|---|---|---|
| 1 | permissions §4 Key part (edge pieces) | Copies of every role commit naming H on X, with X's boxes to H and X's `sync.0`, logged under H's sync ID | H's other readers (an account's second node, a realm's members) start syncing X without an offer | **A stub of X in the unit that references X.** A reader of H gets X only if a unit it syncs references X, or it holds a fire. If no reference exists, H's members learning nothing is correct. Delete the edge pieces. H's own role-class parts stay as H's own role entries. |
| 2 | permissions §4 Key part, 2nd bullet ("tells H's readers of a removal") | A removal's piece under H | A reader of H that no longer syncs X learns it is no longer opened X's sync ID | **Nothing is needed.** A node holding no stub of X has nothing to correct. A node holding X's stub follows X's role entries and gets the removal there, served as a departed member (row 12). |
| 3 | permissions §4 Key part, sync alone; wire §4 `SyncCopyPlaintext`; Sealed form 2 | Edge piece of a sync-only holder as header-less sync copies | requirements "a node granted sync learns the thing's identifier and who granted it", nothing more | **The sync-only cut of a stub.** The wire form stays, renamed with the stub. What carries it changes from H's key part to the unit that references X. |
| 4 | permissions §4 Delivering an edge piece; sync-inbox §2 Sealed copy, §5 Grant from outside; data-model §9 `grant@~0` | Logged under H where the granter may write H. Otherwise a `grant@~0` fire (an offer), or sealed copies for steps, rotations and re-seals | H's nodes hear of a grant, a change, a removal, a new box | **Grants and removals: the grant fire of rule 6** (stub data plus a weak reference), held while the inbox's setting keeps it. Whether a writable H also gets a fire is Drift: delete (core needs no delivery; a signal is optional). **Rotations, re-seals and steps** for holders who cannot open them by the wrap: Q3. The "logged under H's sync ID" branch goes in every case. |
| 5 | permissions §4 Role changes travel, both halves; sync-judgement §2 required set | (a) a role commit naming H travels in H's key part; (b) keys-open travel: it goes under every sync ID whose thing's keys open H (evidence-model finding 19) | A removal on a hop reaches readers of things written through that hop | (a) goes with row 1. (b) is a grant list pushed into the units of H's readers: drop it. Its job is covered by the stubs of the holders on the chain, which carry the hop's removal to every node that reads through the chain. The leftover gap is Q4. |
| 6 | permissions §4 Copies (cut for "an edge piece: key part, stub or public piece") | What a copy on a thing outside the unit holds | Readers get only the boxes they open | **Stays, re-stated per stub:** the cut is the target's `secrets.0` pieces boxing holders the unit's readers open (the public's open boxes always among them), the rest piece where they read, the edge-class parts writing those edges, `sync.0`, and their evidence. Sync-only readers get the sync-only cut. |
| 7 | permissions §4 Logging certificates (sync copies counted; "S carries each sync copy its key part names") | When a logged copy counts | none directly | Re-state for stub copies. Drop the key-part clauses. |
| 8 | permissions §4 Notices; wire §9 Notice; sync-opens §6 (departed served notices); sync-hostile line 16 | Every reader of X logs, under X's sync ID, the removal's copy sealed to the departed member's KEM key | A removed reader learns it was removed (it stops, erases or retains) | This is the target's own data, so the model allows it. It is a second mechanism beside "serve the departed member X's role entries up to its departure" (sync-inbox §5 already names both). Kept as the one way a departed member is told (Q6). |
| 9 | sync-set §2 Stub (built: a strong to a thing the unit holds sync+ on and does not open) | Stub from edge pieces as sync copies | A shared space holding sync on X stores X for its readers | **Rule 2 in full:** strong or weak, opened or held at sync+, and holder stubs on chains. Built from the target's role entries, never from a piece. |
| 10 | sync-set §2 Public pieces | Under T, the public's piece on each X a strong of T reaches | T's readers read public X wherever it is referenced, founded | **Part of X's stub.** The public's boxes are open to everyone, so they are in every cut. Whole carriage includes the stub, so a strong to a public thing founds itself the same way. |
| 11 | sync-set §2 Following by the public entry; sync-opens §4/§5 `by_public`; issues/public-follow-retest-cost | A node reading T follows every X that T's key part names, testing whether the public reads it | A removed holder's unit learns later that X turned public | **Delete** (Q5). Under the model, X's stub reaches T's unit when a node that syncs both logs it. Cost issue dissolves. |
| 12 | sync-set §2 First entry ("or its edge piece in the key part of an own or read thing") | How a node first enters X | Sharing works across an account's nodes | **A unit carrying X (whole or stub), or a held fire** (rule 6 via rule 4). The local part counts as a unit: the node root's references keep their stubs in the node's own store. |
| 13 | sync-set §2 Held for keys, §3 Held for keys no more; sync-opens §4 `keys` source class; sync-ids §6 role entries for a keys holder; sync-judgement §6 moves; commits §5 What a held thing needs | Per node, a walk up from synced C through the holders C's grants name; each holder's role entries pulled from its own sync ID | Writing or reading C through holders without syncing their content | **The stubs of the holders on the chain, carried in the unit** (rule 2's last sentence). The keys source class stays as the "stub" class: following a stub's role entries is the same wire behaviour. What changes: the holder's sync ID and first box come from the stub in the unit, never from an edge piece. The holder set is the chain the unit's keys open by, never "every holder C's grants name". |
| 14 | sync.md §3 Kept for T; Holders by copies | Sync IDs and holders known to a node keeping T unread, from edge pieces' `sync.0` | Stores keep the right sync IDs | From the stub's sync-only cut. |
| 15 | sync-ids §2 (holder through the record edge reaches a newly independent thing's sync ID via the mint admin's key part); §4 Owner (a node keeping g unread takes g's sync IDs from edge pieces) | Promotion of a dependent thing to independent | M's readers keep up with a thing minted in M | M's readers reach X only by M's (or some unit's) reference to X: whole in M's unit, so the stub comes with it. If no reference exists, they have nothing to keep up with. §4: "from the stubs it holds". |
| 16 | sync-inbox §5 Carried commits ("it is in H's key part while held") | Fire contents counted as key part | Offer usable until the fire expires | Rule 4: the held signal's weak reference holds X's stub, which the receiver fetches from X's own sync ID (Q1). Signals carry no commits. |
| 17 | sync-inbox §5 "A grant by a node that may write H needs no fire: logged under H's sync ID" | Writer-of-H branch | A writer granting its own account or realm | Drift: delete (core needs no delivery; a signal is optional). |
| 18 | sync-hostile lines 38, 45-47, 49 | Stated weaknesses phrased by key part | — | Re-state. Line 49 dissolves with sync-alone stated paths (issue sync-alone-stated-path-evidence needs re-judging: the evidence rule stays, but nobody's key part carries it). |
| 19 | crypto §4 Reported/Carried, Holder actors "for keys" | Holder actors' keysets under A's sync IDs | Re-seals work | **Unchanged.** This is target data (A's rotation logs the holder actors' keysets under A). Only the phrase "holds a role for keys" (crypto §3 KEM key due) moves to "holds a role on a thing it is stubbed or synced for". |
| 20 | requirements Sync line 49 ("from the grant's notice or from something it already syncs") | — | — | **Fits the model as written** (notice = the fire; something it syncs = a stub). "Notice" clashes with permissions §4 Notices: use one word at the requirements pass (Tess). Add the stub concept beside the sync unit (stubs.md, for Tess once built). |
| 21 | data-model §8 Held history ("weaks in history count for nothing") | — | — | **Rule 4:** a weak in a held body holds its target's stub. |
| 22 | sync-inbox §1 inbox = `keys.0`-named thing else itself | — | — | **Rule 5:** the inbox is always a thing of its own, strongly referenced. Also settles the dependent-thing case of behaviour-depends-on-own-keys. |
| 23 | API: `Osis::grant` doc "a grant to a thing as holder reaches that thing's readers through it" (core/osis/src/share.rs, read) | API promises key-part delivery | Apps rely on a grant to a realm reaching its members | **Rewrite under notes/api-design.md:** a grant is the target's data; the holder learns of it only if someone sends a signal (an option, may default on) or writes a reference it reads. |
| 24 | notes: holder-access-study (direction 3 and "Why not down": "key part's edge pieces are a bootstrap for siblings"), node-closure (Kept list: "a grant naming a holder in the holder's key part"; Learning a grant), accounts-switch-brief (First entry; the record edge's piece control), certificates, sync-facade (Key part), sync-inbox, write-path-design §2/§231, public-and-cards-brief (Public pieces, Following), a2-spec README (Open 5, 9), mint-admins, keys-rotation, engine-roles, sync-access, sync-unread, sync-opens, terms (sync words) | They describe the built design as the design | — | Rewrite each to the stub design, or delete the obsolete sections (complete refactor, no "formerly"). holder-access-study's key-part paragraphs go and its own title moves onto stubs.md. |

### 1b. Code (from grep counts and file sizes; function names read; roles of whole files partly guessed)
| Mechanism | Where | Fate |
|---|---|---|
| Key part and edge pieces | engine `sync_ids/certs.rs` (769 lines): `Engine::key_part`, `key_part_on`, `edge_pieces_into`, the edge-piece branch of `sync_certificates`, `stubs_of`; `Cut` variants for pieces | Delete the edge-piece paths. Keep `cut_parts` and `Cut` for evidence and keys. Add a stub cut. Rewrite `stubs_of` from rule 2. |
| Delivery | engine `flows/inbox.rs` (1,173): `deliver_copy`, `deliver_sealed`, `fire_copy`, `take_edge_piece`, `EdgePiece`; `flows/offers.rs` (234, pairing offer); `flows/edges.rs` call sites | Delete the key-part logging branch and sealed copies to the holder. Keep one `EdgePiece`-like value, renamed (the stub's first data) for fires and pairing. Q2 decides the sealed-copy replacement (entry boxes recommended). |
| Sync-only copies | commit `sync_copy.rs` (101); blob `blob.rs`/`fire.rs` form 2; engine `sync_ids/unread.rs` (605): `sync_copies_carried`, `Unread::holders` | Keep the form as the sync-only stub cut. `sync_copies_carried` is re-derived from stubs. |
| First entry and stubs in the walk | engine `sync/units.rs` (1,726): `given_by`, `edge_carries`, `held_for_keys`, `named_up`, `follows_public`, `Closure::keys` | Rewrite `given_by`/`edge_carries` to rule 2 (references only, plus held fires). Delete `named_up`, the key-part branches and `follows_public`. `held_for_keys` becomes chain stubs. |
| Sync set | engine `sync/set.rs` (`by_public_alone`), `sync/proofs.rs` (`by_public_alone`), osis-sync `opens/mod.rs` (`Changed::by_public`) | Delete the public-entry following. Keep the public entry as a credential (X's own steps list it). |
| Keys source class | osis-sync `types.rs`, `opens/holds.rs`, `opens/records.rs`, `streams/serve.rs` (`role_entry`), `streams/pull.rs`; proto `msg.rs` `SourceClass::Keys` | Stays, renamed to the stub class (wire value 2 unchanged, or renamed in place: no compat). |
| Notices | engine `sync/notices.rs` (197), `rotation/departures.rs` (311) | Per Q6 (keep, recommended). |
| Keys-open travel | engine `evidence/mod.rs` (section "keys-open travel", ~line 881), `evidence/held.rs:169`; engine tests `tests/it/evidence/{travel,counts,hand}.rs` | Delete if Q4 goes as recommended. |
| Retention of pieces | engine `retention/needed.rs` (`Need::Offered`, key-part needs), `sync/bodies.rs`, `sync/certblobs.rs` | Re-derive needs from stubs and held fires. |
| Lost access and role | engine `rotation/lost.rs` (`grants_count`, `role_here`), `rotation/*` | `grants_count`: where the node syncs the thing or holds its stub. |
| Tests | engine `flows/tests_delivery.rs` (1,268; 90 hits), `apply/tests_validity.rs`, `tests/it/{external,accounts,pairing,closure,scale}.rs`; osis-sync `tests/it/{holding,differential,harness/history,streams,flows,store,grants,growth}.rs` | Delete tests of deleted mechanisms wholesale (tests_delivery mostly goes). Rewrite slimmer around the stub properties (part 4). |
| Models | held-model `closure::entry`, `evidence`, `box_cut`, `copy_cut`, `independent`; TLA `rotation/KemKeys.tla`, `Entry.tla` | M1, M2 done (Model findings). |

Detail: Appendix A.


## Appendix A: code detail (read-only sweep; "guess" = inferred by the sweep)
Not in scope though the grep hits: sync-opens `Msg::Offer`/`OfferItem`; osis-sync `inbox/offers.rs` (deposit offers); `Engine::offer_fire`/`FireOffers` (general sealed fires); stranded notices (`stranded@~0`, `sync/stranded.rs`, TLA "Notice"); `LocalPeer::deliver_sealed` (reseal test helper); `Prefix::for_keys`, `role_for_keys`, `kem::holds_for_keys`, `Cut::Keys`/`Cut::Evidence`; `Engine::role_entry` (also deposit signing).

- **Key part and edge pieces** (engine `sync_ids/certs.rs`): `Cut::EdgePiece` (21), `Certs::sync_copies` (42), the key-part, stub and public-piece lines of `sync_certificates` (158-171), `public_pieced` (184), `stubs_of` (197), `edge_pieces_into` (211), `stub_holders` (233), `key_part`/`key_part_on` (258), `edge_on` (271; also `sync/set.rs` `public_edge`, which notices use), the EdgePiece branch of `cut_parts` (330-365). `flows/inbox.rs` `EdgePiece` (897-941), `edge_piece` (876), `take_edge_piece` (287); `held_pages` stays (ordinary fires use it).
- **Delivery** (`flows/inbox.rs`): `deliver_copy` (25; called from `flows/edges.rs` 220, 363), `deliver_with_steps` and the `node/sync_sent/` rows (51-95), `deliver_step` (111), `deliver_sealed` (128; called from `rotation/mod.rs` 574 `deliver_rotation`, 1104 reseal), `fire_copy` (147), `unowe_grant` (159), `Fire::Grant`/`Fire::Copy` tags 1 and 3, the grant part of `take_fire` and the `gf/` carried rows, `granted_on` (read by `units.rs` 1012, `retention/needed.rs` 305, `rotation/lost.rs` 152), `grant_fires_held`; the copy and notice arms of `sealed_fire`/`take_sealed`; `Need::Offered`.
- **Sync copies**: `core/commit/src/sync_copy.rs` (101, whole file); `sync_ids/unread.rs` (605: rows `su/`, `sync_alone_on`, `syncs_by_copies`, `copies_naming`, `copies_speak` (osis-sync `streams/mod.rs` reads it), `sync_copies_carried`, `seal_sync_copy`, `take_sync_copy`, `unnamed_copy`). `Core::unread` (kept unread in general) stays with its copy-fed parts re-sourced from stubs (guess). osis-sync `read/{mod,ground,live}.rs` sync-copy effects (`sync_copies_due`, `log_sync_copy`).
- **Held for keys**: `units.rs` `Closure::keys`/`for_keys`/`keys_feed` (144, 618), `held_for_keys`/`opened_holder`/`named_up`/`settle_keys` (1208-1292); `Core::keys_came`; engine `Holding::Keys`, `Root::Keys`; perm `Holding::Keys`; osis-sync uses across `opens/holds.rs`, `streams/{relay,pull,serve}.rs`, `store/mod.rs`, `status/mod.rs`. Wire `SourceClass::Keys` = 2 (proto `msg.rs` 179-240) and the member-record byte (`opens/records.rs` 105-122). These stay as the stub class.
- **Stubs, public pieces, following** (`units.rs`): `Closure::beyond` (127, guess: used elsewhere too), `Closure::public`/`follows_public`/`public_feed` (146, 635-647), `edge_carries` (983), `listed_carries`/`names_sync_id`/`own_carried`/`read_carriers`/`pieces_on` (995-1034), `settle_public` (1295-1345), `refetch_holders` (1404), `Carry::Pieced` (899-967). `follows_public` callers: `sync/set.rs`, `sync_ids/actors.rs` 299, `rotation/lost.rs` 152. `Core::public_listed` stays (the public entry in X's own steps; the held branch edits it).
- **Offers / pairing**: `flows/offers.rs` (234, whole file) backs `Osis::offer`/`take_offer` (`core/osis/src/share.rs` 267-300, 763-784), osis-account pairing (`libs/account/src/lib.rs` 372, 429), `local_peer` `pair`. Kept as the by-hand form of the grant fire's stub data. `Pieces::SyncAlone` becomes the sync-only cut.
- **Notices**: `sync/notices.rs` (197, whole file), `rotation/members.rs` `notice_keyset` (477), `flows/inbox.rs` `sealed_notice`/`open_notice` (744, 1003-1053), `Opened::Notice`; blob `fire.rs` `NoticeBody`/`seal_notice` (91-150); crypto `blob.rs` notice box (303-392) and the kdf labels; osis-sync departed serving (`opens/mod.rs` `Member::departed`, `opens/holds.rs` `departure_until`, `streams/serve.rs`). Q6(a) keeps it.
- **Keys-open travel**: engine `evidence/mod.rs` (~881), `evidence/held.rs` 169; tests `tests/it/evidence/{travel,counts,hand}.rs`.
- **Wire only for these**: `SyncCopyPlaintext`; Sealed form 2; Sealed form 1 (the sealed copy; notices use it); the notice blob; `SourceClass::Keys`; the `grant@~0` value (`core/schema/src/core_types.rs` 355); `osis://offer/`; engine rows `su/`, `nt/`, `node/sync_sent/`, `gf/`, fire tags 1 and 3. No vectors cover them.
- **Tests mainly for these**:
  - engine `flows/tests_delivery.rs` (1,268 lines, 35 tests).
  - `apply/tests_validity.rs` 149-365 (6 piece tests).
  - `rotation/tests_stranded.rs` (2 uses).
  - engine `tests/it/accounts.rs` (5 entry tests), `external.rs` (~10 offer tests), `pairing.rs`, `scale.rs` pairing, `closure.rs` `lowered_to_sync_a_thing_is_kept_unread`.
  - osis-sync `holding.rs` (921, 1401, 634, 962), `differential.rs` (400, 600, 610, 677, 693, 760, 793, 823), `streams.rs` 556, `opens.rs` (306, 2295-2382 classes, departed 362/431/2442/2622/2638).
  - Harness `history.rs` (`unoffered`/`pieces`/`named`, the `for_keys` check), `harness/mod.rs` 1236.
  - Indirect (pair through offers): osis-account, chat and app sync tests.
  - Ignored "sync rewrite" tests plausibly touching these (guess): `holding.rs` 537, `retention.rs` 106, `inbox.rs` 923/934, engine `order.rs` 4797/5169.
- **Models**: held-model done (M1); TLA `Entry.tla`, `KemKeys.tla`, `Depth0.tla` `pl`/`kpl` and roles-model `told.rs` done (M2). sim: nothing specific.

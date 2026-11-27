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
| R3 entry | landed; what it built, its choices and what it owes: R3 built, below |
| R4 tests/notes | partly landed: R4 built, below; what is still owed |


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
6. **A grant signal carries values only:** X (a weak reference), X's sync ID, peer hints: X's public link's values. The receiver follows X's sync ID by role while the signal is held, enters at a reader of X by its grant's notice (point 10), and holds X's stub.
7. **Public things.** Covered by the stub (point 1). The public entry in X's own steps stays.
8. **Second node of an account.** Pairing hands over A's public link by hand (the signal's values). The node strongs A from its root, enters A by role at any reader of A, and A's unit carries everything A references, whole or as stubs, with the chain-holder stubs. A's inbox is a thing A references (rule 5), so held signals come with it.
9. **Local part.** The node root's references keep their stubs in the node's own store. This replaces the record-edge piece.
10. **Notices** tell departed members (Q6) and holders that cannot open a commit boxing them by its wrap (grantees, re-sealed holders, sync-only holders): X's own entries, sealed to the holder, served by role; never under the holder's sync ID.

## 3. Questions (working answer: each recommendation; Tess may revise)
**Q1, Q2 (how a signalled holder gets in; holders that cannot open a re-seal or rotation by its wrap)**: answered by M2 (Model findings M2): the notice form served by role, for Tess. Built as R3 built says; one deviation from the model: each told (commit, holder) is a notice entry of its own beside the commit, not a sealed key inside the commit's blob, so a store sees one more entry (the commit's blob keys its sections under read secrets, so the holder needs a copy openable by the blob key: a notice is that copy). Rejected: entry boxes in X's steps (M2: every store counts holders and grants by them).

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

Owed by R2 (not built): a departed stub holder told of its removal (the two-hop chain's U removed from R reaches node 1 only as a departed member, by notices); `stubs::a_two_hop_chain_*` asserts only that nothing written since is read.

## R3 built
Rules (each once): spec/permissions.md §4 Notices (a role commit **tells** a holder its departure or its boxes), §3 (a holder that cannot open a commit boxing it takes it by its notice), §8 Pairing (A's public link, redeemed for the node root); spec/sync-inbox.md §5 Grant signal; spec/data-model.md §9 (`grant@~0` value); spec/sync-set.md §2 First entry, §4 Redeeming (a public link **reaches** its target: public reads, or the node holds a role), §5 Source; spec/sync-opens.md §4 J, §5 ByRole, §6 (a member by J stays while its side follows S by a public link alone); spec/crypto.md §3 (KEM keys sticky), §5; spec/wire.md §10; spec/commits.md §5 (a signalled thing is held for itself); spec/sync-hostile.md §2. Words: notes/terms.md (Notice, Public link, Grant signal).

Code:
- Notices (`sync/notices.rs` `boxed_unopened`): every reader of X computes, per held role commit c on X and current holder M it boxes, whether M opens c by its wrap here (`wrapped_at`): some other held commit boxes M at read at that epoch after M's newest removal, or boxes the public there, or the epoch is derived from X's mint admin's and M is that mint admin. Else c's notice to M (cut `Cut::Told`: edge-class parts, M's piece, the rest piece) is carried. A node opening a notice by its wrap notes its row and takes nothing (`open_notice_in`: a reader taking a holder's cut before the commit itself broke its reading); one opening it by KEM takes it. The KEM keys tried are those of X's holders here and of the node's own chains (`own_chains`).
- Entry by role: a public link followed with no read secret of its thing held sets `ReadCredentials::by_role` / `Creds::by_role`; osis-sync sends ByRole for such S to every peer where no Hit on S goes (the public entry's box comes only with its Hit), opens on acceptance, and keeps that member while `by_role`; a receiver accepts ByRole from J reader or sync holder.
- Pairing: the pairer hands over A's public link (`Engine::public_link` no longer requires the public's read); the new node writes the strong and settings (`take_pairing`, `Joining::finish`, now async) and redeems the link for its node root; the redeem is Held once the closure holds A and the link reaches it (`Engine::reaches`). `Driver::offered` and its rows' entry point are gone.
- Grant signal: `Engine::signal_grant` owes a `grant@~0` fire on the holder's inbox; `Osis::grant` sends it unless `GrantOpts::quiet` (doc rewritten: promises nothing of holders learning). A held valid signal is followed (`FollowedLinks::follow_signal`, rows `sg/`, loaded at the first `take_carried`), let go when no longer held valid (`drop_signals`), rooted for retention (`Root::Signalled`), and its thing held as a stub once entered (`thing_holdings`).
- KEM keys: `rotation::kem::publishes` also where the current keyset of the role carries one.

Choices taken (simpler option; Tess may revise):
- **Notices are the one mechanism** for departures and for boxes a holder cannot open by the wrap; logged by every reader judging it, as departures were. A store sees one more entry per told (commit, holder) beside the commit; a reader's judgement of "opens by its wrap" can differ from another's (extra notices cost bytes only).
- **The pairing and signal values are a public link**: one form (thing, sync ID, peers); redeeming one enters by the public entry or by role. `Osis::public_link` names any thing with keys of its own.
- **Trust records are not handed over in pairing**: a new node takes sides by spec/permissions.md §5.1 as commits reach it. Open for Tess under "one side per fork, sides stick": a dispute the pairer had settled may show again at the new node.
- **An entering node names S in ByRole to every peer it meets** (it can judge none): a stated leak of interest in S (spec/sync-hostile.md §2). Restricting to the value's peers would make a stale hint final.

Owed (R4, or a fresh R3b):
- Sync-only holders and stopped stores catching up by role (spec/sync-judgement.md §6 Stops: a store past its keys opening S by role at a reader and taking its rotation's notice by KEM): not built; `Unread` takes no notice. TLA `NT_sync_next` says it is needed.
- Grant signal peers as dial hints (`Engine::signal_hints` exists; osis-sync `Inbox::dial_hints` does not read it).
- Weaks in held history holding stubs (spec/data-model.md §8 Held history, rule 4; `refs::kept` follows strongs alone): a held signal holds its stub by its own root instead (`Root::Signalled`).
- `differential::a_reader_by_the_publics_box_reads_across_a_start_*` (ignored): once node 2 (paired) enters account 0 by role, node 1, redeeming a public link to thing 0, holds its minting and no role entry of it; passes when node 2 never enters. Cause not found. It passes once the history's grant to node 1 is told (R4's `give`).
- `grants::a_reader_granted_again_reads_again_*` (ignored): a holder removed, told, re-granted and told again is not served its new grant's notice (its peer still judges it departed where served).
- `app sync::remote_delete_of_the_open_thing` (ignored): fails once paired by the account's link; cause not sorted.

## R4 built
- **Differential oracle** (osis-sync `harness/history.rs`; notes/test-properties.md, Reference-graph differential): held-model `closure::entry` under `Rule::BUILT` (R2's strong-by-role choice as a rule of the model), one node per account; a grant to an account is told (`Engine::signal_grant`), one to a thing or the public is not. Default size: 5 of 6 seeds hold, seed 2 is R3b's class. Full size: issues/differential-full-size-classes.md.
- **Tests**: a grant a test means told is told (`harness::told`, the history's `give`); ignored tests are re-judged, each still ignored naming its cause (`tools/ignores.py "stub rewrite: "`). Tests asserting only that nothing reaches a grantee passed vacuously while grants were untold; those now failing name their cause.
- **Controls**: `stubs::a_three_hop_chain_*` proves chain stubs (R2 named only in a stub's roster); `differential::a_reader_by_the_publics_box_reads_no_more_once_lowered_*` fails with the listing counted whatever its head.
- **Pairing checked**: `World::pairs_entered`, at each quiet run.
- `tools/policy.py` refuses the deleted words in every file.

Still owed:
- **R3b**: a held grant signal holds S as Read whatever the node holds (`thing_sync_now`'s followed-link branch; `thing_holdings` gives Stub only with a read secret): sync-only grantees and removed holders. Tests ignored `stub rewrite: a signalled sync-only holder holds S as Read (R3b)`; 46 of the full-size differential's 70 failing seeds.
- Engine ignored tests (13: removed holders, keyless grants, unsorted) and app `remote_delete_of_the_open_thing`, not re-judged.
- `public::removing_the_public_ends_*` (ignored): with node 0 cut off, P's removal never reaches node 2 through node 1's store of T. Including a unit's independent members in `Closure::unit_stubs` (carrying X whole includes its stub) did not change it; cause not found.

Open for Tess (simpler option taken: the spec as written):
- **A role record's holders are references** (spec/data-model.md §8 What counts: `roles.0`'s holders are weaks), so a unit carrying X holds the stub of every holder in X's roster its keys open or it holds sync on: a grant-driven stub the model has none of (a grant is its target's data; held-model's `Chains::Up` control is that rule). It makes the chain-holder rule redundant for the first hop and gives stubs of holders on no chain (full-size seeds 70, 73). Dropping core aspects' holder weaks from what counts would match the model.

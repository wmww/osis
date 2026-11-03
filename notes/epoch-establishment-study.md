# Epoch establishment: threat model, counterexamples, frozen coverage
> Summary: Design study of spec/crypto.md §4 establishment and covers. Three counterexamples to the keyset-names branch (one with no forgery, one on main too, one the later-admin-path hole): each has a node relying on, or re-sealing against, a departure that the commit it relies on was not made knowing. Fix, "frozen coverage": a rotation or grant covers exactly the departures it names; a node relies on nothing else and re-seals a holder actor only knowing what every earlier boxer of it knew. Deletes the box-inspection covers rule, the written-by-a-departed-party clauses and the complete-pass guard's safety role. Residual: the compaction class. Privacy of names, TLA gaps, two scenarios to add.

Reads: spec/crypto.md §3-§5, spec/permissions.md §1-§6, the `keyset-names` branch diff, issues/epoch-establishment-redesign.md, issues/keyset-names-start-escape.md, core/test/tla/rotation, the second review's two breaks (owner chain through a plain thing, admin path added after the rotation). Analysis only; nothing run.

## 1. Threat model and properties
Notation: actor A, role r, epoch e with secret s_e, rotator R_e, Names(e) = the names in e's history box, Names(e)↓ = those commits plus everything ordered before a named epoch start of its thing plus e's departs mark. A **departure** d is a commit (lowering edge write, passed `until`, snapshot dropping a holder) whose party D now reaches less than r on A; D may be a direct holder of A or sit below a holder actor N (device of N, holder of a holder, any depth, through plain things and owner links too).

Adversary:
- **Withholding**: any host or peer delivers any subset of commits in any order, forever. The projections of one commit (its `roles.0` certificate copy, its `keys.0` certificate copy, its label copy, its inbox copy) are separate blobs and arrive or vanish separately. A "complete pass" is complete only relative to the hosts a node reaches.
- **Departed party D** holds every secret it was boxed at, everything those history boxes carry, its signing key, and the plaintext of every commit wrapped under those secrets: rotation commits are wrapped under the epoch they supersede (crypto §5), so D reads later epoch ids, keysets and deposit seeds, never later secrets.
- **Forgery**: D signs any role commit. Where D's departure d is held (or an epoch start after it), D's writes dated after d are invalid and dated before d are invalid unless d's frontier (or the ledger tenure's, permissions §6) covers them. Where d is not held, every such write is valid: a rotation of A or N boxing D, a `keys.0` keyset of N with D's KEM key under any epoch id (`keys.0` vouches for no secret), a grant to a second identity, a stranded heartbeat.
- **Honest ignorance** does the same damage without forgery: an admin of N that has not seen D's removal forks N boxing D; an admin of A that holds N's new keyset but not the removal boxes N at whatever `keys.0` shows.

Out of scope (Tess): a current admin or writer acting maliciously; a party that keeps a role by another path (not departed).

**Safety (NoLeak)**: if an honest node W encrypts under e while it knows d, D never learns s_e; and a D that never held a role on A never learns any s_e (the later-admin-path case needs this second half). s_e travels only in e's boxes, in later grant or re-seal boxes at e, and in history boxes of epochs whose rotator held s_e, so the property is: nobody who writes any of those boxes seals one to a key D can derive, unless an admin re-grants D.

**Liveness**: a role with one honest node that may rotate it reaches, by that node's own rotations alone, an epoch that node uses; other honest holders establish it once they hold what the rotator placed with it.

## 2. Verdict on the branch rule: unsound
The branch (names of departures from A and everything below, keyset names by epoch) closes what it set out to close: the start escape of issues/keyset-names-start-escape.md (a keyset name is met only by a held valid `keys.0` body writing or superseding the epoch) and a departed N-admin's forged keyset **when R_e held the removal** (then every establisher holds it and the forgery is invalid there). It keeps the box-inspection covers rule and names only what the rotator held at rotation time; both fail. Every counterexample has one shape: a node relies on a box or epoch for a departure that the commit it relies on was not made knowing.

### C1. Honest fork of a holder actor (no forgery)
Group A; person actor M holds read on A; M's devices D, D2, Z. R, W, X admins of A, none of M.
1. D2 removes D from M: C_M = removal + rotation of M's read f_old → f_new + M's `keys.0` (f_new). It reaches A's label as two certificate copies, the `roles.0` edge delta and the `keys.0` delta (permissions §2-§4).
2. R receives the `keys.0` copy only (the `roles.0` copy withheld or later; or f_new came through M's chain certificate, which carries M's current `keys.0` commit and no edge write on (D, M), since D is not on D2's path). R rotates A → e for an unrelated reason, boxing M at f_new. Names(e): keyset name (M, read, f_new); no departure from M.
3. W holds C_M whole and e. Branch covers: M's box at e names f_new, the newest keyset W holds, set by the commit that made the departure → covers. W writes content under e knowing d.
4. Z, not yet holding C_M, rotates M for another reason: fork f' at f_new's n, boxing D, `keys.0` ← f' (later `ts`, wins LWW). Writing on A's label as M, Z places M's current `keys.0` commit (f') there.
5. X holds e (boxed, so s_e), C_M's `keys.0` copy, f'. e establishes at X: valid rotation commit, keyset name met by C_M's body. X knows no departure inside M; its newest keyset of M is f'.
6. X rotates A → e' (grant, eager, unrelated departure): history {s_e, …}, M boxed at f'.
7. D opens the box at f', then s_e from the history box, then W's content. Every node honest; one blob late at R, two at X.

**C1'** (forgery, no fork): step 4 becomes D writing M's keyset {f_D = (n_new + 1, nonce), kem_D, supersedes [f_new]} dated after C_M; valid at X, meets the keyset name through `supersedes`. The branch's names of departures below help only when R_e held the departure; here it did not.

### C2. Fork-sibling re-seal (on main too)
Direct holders only; this is the one the TLA model can find.
1. G grants D read at e0. a2 rotates A → e1 before reading the grant: e1 boxes {a1, a2, m1}, not D.
2. a1 holds the grant, not e1, and removes D: C_D = removal + rotation e2 superseding e0; e1 and e2 fork at one n.
3. W (a1, or anyone holding e1, e2, C_D) takes e1 as newest (lower nonce, half the time). e1 holds no box for D → covers. W writes under e1 knowing d.
4. a2 holds e1 and the grant, not C_D (not yet uploaded, or on another host). After a complete pass of its hosts it sees current holder D without a box at e1 and re-seals it (permissions §3).
5. D reads W's content. Names(e1) is silent on d because a2 never knew it. Any rule that lets "no box for D" count as covering has this hole: a missing box means "excluded" or "unknown", and the one-commit rule disambiguates only along the chain through the removal, never across a fork.

### C3. Admin path added after the rotation (the second review's open break)
1. D leaves person actor N (C_N, rotating N to f_new) while N holds nothing on A. R rotates A → e; N is not below A, so Names(e) says nothing about N.
2. G, holding C_N, grants N a role on A at e, boxing N at f_new (covers, by G's judgement). G places N's `keys.0` (f_new) under A's label; C_N's `roles.0` copy is late or withheld at X.
3. X holds the grant and f' (an ignorant fork of N boxing D, as C1 step 4) or D's forged f_D. X re-seals N at e, or rotates A boxing N, at f'. D, never a holder of A, reads everything under e.
Nothing in e's names can speak about N; the knowledge G had (C_N) must travel with G's grant, and the branch's grant carries none. The same shape arises when N gains a path to A through A's owner or a plain thing after the rotation.

### Other checks
- **e1/e2 re-current** (nomination): the branch reads e1's coverage from boxes again once e2 falls, the same shape as C2. Under §3 no rule about successors is needed: whichever epoch is current, a node relies on it only for what it names; a secret that passes the nonce rule and whose valid rotation commit is held is genuine whatever invalid history box it also came through.
- **Removed N-admin forging N's `keys.0`**: closed by the branch iff R_e held and named the removal (C1' otherwise). Under §3 the condition becomes "iff somebody relied on it knowing", which is the right one.
- **Owner chain through a plain thing**: covered by "things below A, whether or not they have secrets of their own" (fixed on the branch; §3 keeps that definition).
- **issues/fork-held-by-non-rotators.md**: liveness and readability only.

## 3. Simplest sound rule: frozen coverage
One principle, applied to the two things that carry a secret to a holder: **knowledge travels with the seal; a node relies on a seal only for what its maker knew, and re-seals only knowing at least what every earlier sealer knew.** Keep the branch's names as the carrier; change how they are used.

**Names.** A rotation of A names, in its history boxes, what the branch names: A's epoch start, every lowering write, passed `until` and audit drop on A and on every thing below A (holders and their holders, owners, plain things, since each thing's epoch start at the rotator), the departs mark, and per boxed holder actor its keyset epoch. New: a **grant or re-seal of a holder actor N carries the same names for N** (N's epoch start at the granter, departures inside N it holds, the keyset epoch it seals to), in its `secrets.0` delta beside the box. Key actors (devices, link and recovery keys) carry nothing.

**Establish** (as the branch): e is established at X when X holds its valid rotation commit or a `secrets.0` snapshot keying it, headroom holds, and, if X holds s_e, some live history entry's names are met: departure names applied with the `roles.0` delta on the named thing or ordered before X's epoch start of it; keyset names by a held valid `keys.0` body writing or superseding the epoch; departs mark held.

**Rely** (replaces the covers rule). e covers departure d at X iff d ∈ Names(e)↓. A node that may rotate r MUST NOT encrypt under an epoch of r that does not cover a departure it knows of; it rotates first. Boxes decide nothing; a holder actor granted after e is covered for nothing inside it (the next writer that knows a departure inside it rotates).

**Box a holder actor.** X seals A's secret to N (rotation, grant, re-seal) only when it holds the names carried for N by every held valid box to N at a current epoch of A (grants and re-seals; a rotation's are held through establishment), and only at N's newest valid keyset at X if X judges that keyset covers every departure inside N it knows, by today's local rule (a non-holder of N counts a keyset as boxing a departed holder unless the departure's own commit set it or X holds its `secrets.0` delta boxing none); else N is left out (permissions §3). This chooses the key; it no longer decides whether e may be used.

### Proof sketch
Invariant: every box that carries s_e (e's own, a later grant or re-seal at e, a history box of an e' ∋ s_e) is sealed to no key D can derive, for every d ∈ Names(e)↓ and every d named by a held box to N that the sealer had to hold.
- The sealer X established e, so X holds d or has an epoch start of d's thing after it. Direct D: not in X's roster; D's forged grants of itself are audited by d's frontier or the ledger's; a genuine re-grant is the exclusion in §1.
- D inside N: X seals to a keyset f valid at X. f by D or through D's lost edge: invalid at X. f by an admin of N that knew d: induction on the box chain (N's own epochs obey the same rule). f by an admin that did not know d: f boxes D or a D-reachable keyset, X knows d and counts f as boxing D, N is left out.
- Reliance: W writes under e knowing d only if d ∈ Names(e)↓, so the invariant guards every box of s_e. For N granted after e, nobody relies on e for departures inside N; the grant's box is D-safe by G's judgement, and every later box to N is made holding G's names.
Forks: siblings have independent names; a writer on the sibling checks the sibling's. Snapshots: a name met by an epoch start means the roster already lacks D or lists D's ended tenure with its frontier. Late joiners: a grant copies e's history box (its names) and carries its own for the grantee; the rotator and granter place the named commits under the labels they place the commit under. Re-currence: no rule. ∎

Liveness: an honest rotator's own epoch names everything it knows, so it uses it at once and rotates again exactly when it learns an unnamed relevant departure; one commit, no dependency on others. Two rotators alternate at most once per departure one knows and the other does not: each epoch names a superset of what its predecessor named plus what the rotator learned, and departures are finite.

### What it deletes
- crypto §4 covers rule: "holds no box for M", the recursive box walk for direct departures, the "written by a departed party" clause and its "counts the epoch as written by each departed party whose chain's first actor…" sub-clause (validity plus frozen coverage subsume them: a departed rotator's backdated commit is invalid wherever its departure is held, and nobody relies on its epoch for a departure it did not name). Engine: `departures::written_by`, `Judge::departed_wrote`, `could_rotate`, `epoch_intro`'s covers role.
- The complete-pass guard on re-seals stops carrying safety (a re-sealer of H at e holds every departure of H anyone relied on, so it sees H departed); keep it as churn policy or drop it.
- Box knowledge (`Holders`, withheld grants) stops mattering for direct holders.

### Costs against the branch
- Wire: names on grant and re-seal boxes of holder actors (today's history-box copy already travels with them; this adds the granter's own list, typically empty or a few entries). Per box: the names of that holder's closure. Code: less.
- Extra rotations: a node rotates when it knows a relevant departure the current epoch's rotator did not name, even if the boxes already exclude the party: a concurrent grant + rotation + removal (C2), a keyset that reached the rotator without the removal (C1), a holder actor granted after the rotation with departures since its epoch start (C3; a person whose roster was snapshotted since its last device removal names nothing, so costs nothing), an `until` passing after the rotation (rotates today too). One commit each.
- Waits: a node that may not rotate and knows an unnamed departure is stranded until a rotator acts (as today when the epoch boxes the party). A node may box N only after holding every current boxer's names for N; they are placed with the box; a late joiner past `ROLE_KEEP` holds them through N's roster snapshot (the start escape) or leaves N out until re-sealed by one that does.
- Names are a superset of relevant departures (re-granted holders included); the rely check compares the commit key the timeline attributes the departure to (the lowering write, the until-setting write, the snapshot that dropped the holder). A superset only costs liveness.

### Privacy
Names put, under A's read secret, the key (ts, node, commit id) of every departure in A's holder closure since each thing's epoch start, in every history box and every grant's copy of it: a reader of A learns each member's device churn. Weigh against what the spec already exposes: permissions §3 makes the remover place the removal and new `keys.0` as certificates under every label the removed party could read, and §4's exception places inside-holder revokes under A's uncovered epoch; a relevant departure's party could read A through N, so its removal is already placed under A's label (readable by the departed party itself), retained `ROLE_KEEP` and then replaced by snapshots. The marginal exposure is retention (names live in the epoch state until A's next roster snapshot of each thing resets them) and completeness (a remover that never tracked A's label placed nothing there). Two ways to reveal less, each sound:
- Names under the **write** secret: `kdf("names", s_write)` of the epoch written beside the history box and the holder box. Readers establish by rotation commit alone (they encrypt nothing but heartbeats) and need no names; writers and admins read them. Cost: an invite holder with read-only invite cannot read or write names, so it boxes no holder actor (key-actor grantees only); the actor it grants is re-sealed by the next writer. Recommended if that delay is acceptable.
- Name the **holder's keyset and epoch start only** for things below A and rely on the ledger: rejected; readers' tenures are not in the ledger, and an ignorant fork boxing a departed reader is then invisible to the boxer (the residual below, made systematic).
Shrinking the set below "every departure in the closure" is not possible: a boxer of N must reject every keyset by a departed party and every ignorant fork, and both need the departure's identity.

### Residual (compaction class) and a 15-byte option
A name met only through an epoch start of N tells X that something ended at that key, not who left. If N's `keys.0` at X shows an honest ignorant fork f' boxing D and X holds neither old boxes of N nor a ledger tenure for D (readers have none), X seals to f'. The same happens one level down when a sub-holder joined N's owner after A's epoch and no A-level boxer knew. This is the accepted post-compaction residue of notes/sync.md Limits (an incomplete view boxes a departed holder; N's next knowing rotation merges the fork and heals it). To close it: departure names carry the departed holder's tid, so a name met by the start still feeds `departures` and the conservative keyset judgement. A supersession-chain constraint (seal only to a keyset that transitively supersedes the named one) was considered and rejected: `keys.0` compaction drops the chain and strands late joiners.

### Dependency to confirm
The forgery argument needs permissions §5.2 to treat D's demotion on N as D's demotion on every thing D reached through N (the frontier text says so). A demotion by `until` or self-removal audits nothing, so such a party's pre-departure writes stay valid: fine, it was a holder; its post-departure writes have no authority and a backdated one stands until the next explicit write on the edge audits it. Existing accepted gap (notes/permissions.md Revocation), not new.

### Other framings considered
- Establishment from the node's own timeline, no names: a node cannot know what it has not received; the rotator must say what it held, and names are the minimal fetchable form. A receipt frontier of role commits (the demotion mechanism) would carry the same with more bytes.
- Rotator sends a roster hash: detects a mismatch, cannot be repaired.
- Treat unestablished history as untrusted: already so (reading-only secrets); not the hole.
- Grant of a churned holder actor as a rotation (grant + rotation in one commit, like removal + rotation): does not remove the need for grant names (an ignorant node still re-seals the grantee at the older epoch, C3 step 3) and costs a full rotation per grant.

## 4. TLA model coverage
Rotation.tla (main): one actor, read role, direct holders, one host, no snapshots or `secrets.0` compaction, rotation commits valid forever, no demotion or `until`, establishment = chain rule, covers = per-node box inspection (`Covers`, `Holders`). It cannot see C1 or C3 (no holder actors or keysets; the branch's forged-keyset extension is the right direction but needs a second actor with a fork of its own and a grant after a rotation) and does not run C2 (the constants allow it; no cfg puts a holder in both `Late` and `Departing`).

Add, in order of value:
1. **C2**: `MC_grant_remove` with `Departing = {"m2"}` (m2 also `Late`), `MaxE = 2`, `Writes = 1`, log order. Expected: `NoLeak` fails on main and on the branch in about ten steps (a1 grants m2; a2 rotates e1 before reading the grant and uploads; a1 removes m2 as e2 superseding 0; a1 receives e1 and writes under it, the lower id; a2 reads the grant, completes its pass with e2 not yet uploaded, re-seals m2 at e1). Under frozen coverage `Covers(x, e)` is `dep[x] ⊆ ep[e].names` with `names = dep[a] ∪ R` at rotation, and a1 is forced to rotate.
2. **Two actors**: N a holder of A with its own read epochs and `keys.0` (LWW keyset, forkable), N's devices as holders of N, A's rotations and grants boxing N at the keyset the boxer holds, a device removal from N delivered to A's admins as two separately withholdable parts, and a grant of N after a rotation of A. Checks C1, C1', C3 and the keyset-name rule itself. One host, log order; the state space is dominated by the two LWW races.
Also worth a cfg: a backdated demotion that invalidates a held rotation commit (re-currence), which needs validity in the model (`kn` entries that can turn invalid).

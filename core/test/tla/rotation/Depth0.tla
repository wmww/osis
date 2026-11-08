-------------------------------- MODULE Depth0 --------------------------------
(* Depth-0 sealing (notes/keys-requirements-study.md, Q2 decided A): a        *)
(* rotation, re-seal or write of actor a never looks inside a holder actor h  *)
(* past what the node itself holds: an epoch of h whose secret it holds and  *)
(* that misses a departure from h it knows is blocked (Blocked), and so is   *)
(* one boxing an actor at a blocked epoch (sealing there was encrypting      *)
(* under it); h is left out of a rotation at a blocked keyset.              *)
(* It seals h at h's newest valid keyset it holds that is or lists every     *)
(* keyset the boxes to h at a's current epochs name (anchors); a box of the   *)
(* epoch it would encrypt under is stale when the keyset it names is invalid *)
(* or listed as superseded by a held valid keyset, and then it rotates first; *)
(* an admin rotates while it holds more than one current epoch (merge);     *)
(* a rotation finding no keyset of h descending from every anchor waits, and *)
(* any removal may go without its rotation (a superset of the built cases: a *)
(* self-removal, Seal waiting, Authority failing).                           *)
(* Rotating needs only the right to rotate (notes/crypto.md): a rotation     *)
(* supersedes every current epoch, those whose secret the rotator lacks too  *)
(* (such an epoch covers nothing at it: it rotates), and any holder of an    *)
(* earlier secret that no history entry of a current epoch it holds lists    *)
(* adds one (HistAdd), unless that epoch is blocked at it.                   *)
(* Every rule judges the boxes a node holds valid. Role cycles (rule 4,      *)
(* notes/crypto.md (Holder actors at depth 0)):                                                   *)
(* no key cycles: actor grants in an agreed order, one closing a cycle over  *)
(* the earlier ones gives no key access, judged over the grants a node     *)
(* holds; a keyset boxing a holder without key access is stale (taint).     *)
(* A writer through holder actors rotates only sealing a holder actor at a   *)
(* keyset whose secret it holds (possession); a writer that wrote a plain   *)
(* thing under a derived secret no current epoch's history carries merges   *)
(* it.                                                                       *)
(* Several actors, read role only; an actor's keyset is its read epoch (boxes *)
(* to h at keyset k open with epoch k's secret). Crypto is access: a node's   *)
(* secrets are the closure, from its device key, over the boxes and history   *)
(* boxes of the commits it holds; a removed device's reach is the same        *)
(* closure over every box ever written. Coverage of a's own departures is     *)
(* frozen (an epoch covers the departures its rotator knew); establishment,   *)
(* hosts, steps and claims are Rotation.tla's and left out here.              *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS ActSeq,     \* actor names; initial epoch i is ActSeq[i]'s
          Mem,        \* {<<actor, holder>>}: direct holders (devices, actors)
          Adm,        \* {<<actor, device>>}: admins (rotate, re-seal, write);
                      \* each is a direct device holder of its actor
          Learners,   \* honest devices: learn commits, act
          Deps,       \* {<<device, actor, remover>>}: removals, once each
          Eager,      \* {<<device, actor>>}: one unprompted rotation each
                      \* (an ignorant fork when made before the removal)
          Forgers,    \* removed devices (admins of what they left) that write
                      \* a keyset of it once, listing every keyset made
          WriteTo,    \* actors content is written to
          Writes,     \* bound on content writes
          MaxE,       \* bound on epochs, initial ones included
          Grants,     \* rule 4: the actor edges of Mem in the agreed order
          Hidden,     \* rule 4: {<<node, edge>>}: grants a node does not
                      \* hold at first (it learns them later); a device's
                      \* grant listed in Grants is held the same way (a
                      \* concurrent grant: a rotation by a node lacking it
                      \* leaves the device out)
          MaxBlind,   \* rule 4: bound on blind boxes (to a holder with no
                      \* key access, sealed by a node missing a grant): the
                      \* ignorance window, as one-shot adversary steps
          Via,        \* {<<device, actor>>}: writers of the actor through
                      \* holder actors (rotate, re-seal, write while they do
                      \* not know a removal of theirs from an actor holding it)
          NoSync,     \* {<<node, actor>>}: labels a node does not sync; it
                      \* learns an actor's commits under its own label or a
                      \* target's (keys.0 of a holder), placements under its own
          Split,      \* TRUE: a holder's keys.0 under a target's label
                      \* arrives without the keysets it names (they are
                      \* carried under the holder's own label only)
          MaxRace,    \* bound on fork merges made by a node lacking an epoch
                      \* of the actor (two merges racing fork again): the
                      \* concurrency window, as adversary steps
          Walk,       \* Blocked's box clause (issues/blocked-walk-stops-at-
                      \* readers.md): "rotator" (an epoch boxing an actor at a
                      \* blocked keyset is blocked only where the node may
                      \* rotate it), "out" (wherever the node holds it; Seal
                      \* leaves the actor out), "wait" (as "out", but a node
                      \* that may not rotate the actor at the blocked keyset
                      \* makes no rotation leaving it out: it waits), "mark"
                      \* (as "out", and the rotation records the keyset it left
                      \* the actor out at; Seal then takes only a keyset listing
                      \* it, by any node)
          FirstAdm,   \* {<<thing, actor>>}: first-admin record edges (in Mem
                      \* and Grants, ordered before every other grant)
          Plain,      \* {<<thing, actor>>}: the thing was plain, deriving its
                      \* secrets from its first admin; its initial epoch is
                      \* its own-secrets rotation, history boxing the derived
                      \* secret of the first admin's initial epoch
          Unaware     \* {<<node, actor>>}: the node lacks the actor's initial
                      \* epoch at first (learns it fairly); a plain thing it
                      \* holds no own epoch of is plain to it: it writes under
                      \* the derived secret of the first admin's newest epoch

Acts == {ActSeq[i] : i \in 1..Len(ActSeq)}
PlainActs == {q[1] : q \in Plain}
PlainOf(t) == CHOOSE f \in Acts : <<t, f>> \in Plain
\* an actor edge removal: <<holder actor, target, remover>> in Deps
ActDep(dp) == dp[1] \in Acts
Holders(a) == {m[2] : m \in {q \in Mem : q[1] = a}}
ActHolders(a) == Holders(a) \cap Acts

Named(bs) == {b.key.k : b \in {c \in bs : c.key.t = "k"}}

RECURSIVE Fix(_, _)
Fix(F(_), S) == LET T == F(S) IN IF T = S THEN S ELSE Fix(F, T)

\* actors holding h, transitively (h itself only on a cycle)
HClos(h) == Fix(LAMBDA S : S \cup UNION {ActHolders(b) : b \in S}, ActHolders(h))

\* rule 4: over edge set E (<<a, h>>: h holds a role on a), the actors whose
\* secrets h's key yields; greedy in the agreed order over the grants G held:
\* a grant whose holder's key a's key already yields gives no key access
GAll == {Grants[i] : i \in 1..Len(Grants)}
ASSUME \A i, j \in 1..Len(Grants) : (Grants[j] \in FirstAdm /\ Grants[i] \notin FirstAdm) => j < i
ASSUME FirstAdm \subseteq GAll /\ Plain \subseteq FirstAdm
\* grants some node lacks at first are made later: initial epochs do not box
\* them, a hidden grant's box is a knowing admin's re-seal (an instance
\* overrides GLate with {} for grants made before the initial epoch, which
\* a node lacks only at first)
GLate == {q[2] : q \in Hidden}
Yields(E, h) == Fix(LAMBDA S : S \cup {q[1] : q \in {r \in E : r[2] \in S}}, {h})
RECURSIVE KeyedTo(_, _)
KeyedTo(G, i) == IF i = 0 THEN {} ELSE
  LET E == KeyedTo(G, i - 1)
      g == Grants[i]
  IN IF g \in G /\ g[2] \notin Yields(E, g[1]) THEN E \cup {g} ELSE E
\* (a constant table: TLC evaluates it once)
KeyMap == [G \in SUBSET GAll |-> LET E == KeyedTo(G, Len(Grants)) IN
             [a \in Acts |-> {h \in Holders(a) : (h \notin Acts /\ <<a, h>> \notin GAll) \/ <<a, h>> \in E}]]
KeyIn(G, a) == KeyMap[G][a]
GNow(dn) == GAll \ {<<dp[2], dp[1]>> : dp \in {q \in dn : ActDep(q)}}

\* spec/crypto.md §4 Holder actors, Carried (the stated limit): a rotation may
\* be learned before the keysets its boxes name (carried as separate blobs);
\* FALSE: they come along
Late == FALSE
\* a half-valid rotation (issues/half-valid-rotation-leak.md): HalfForgers
\* {<<device, holder actor S, actor M>>}: the device, reaching M only through
\* S, removes S from M in a commit rotating M whose secrets.0 part fails
\* Authority (S departing, nothing shows it); the rotation boxes nobody, lists
\* every honest keyset of M and makes the removal known. HalfMode: "keyset"
\* (its keyset is held valid, its epoch established nowhere), "rotation" (the
\* whole rotation is invalid where judged: at nodes syncing M, which hold its
\* secrets.0 part; elsewhere as "keyset"), "keys" (invalid wherever its keyset
\* is held: the Authority evidence travels with the keyset)
HalfForgers == {}
HalfMode == "keyset"
\* spec/crypto.md §4 Encrypting under: a box carrying an epoch's secret is
\* encrypted under its recipient's key, not under that epoch, so a re-seal
\* boxes a current holder at every current epoch whose secret the node holds,
\* a blocked one included (at a keyset Seal allows: nobody new reads under the
\* epoch); FALSE: carrying counts as encrypting under the carried epoch
CarryFree == TRUE

DK(d) == [t |-> "d", d |-> d, k |-> 0]
KK(k) == [t |-> "k", d |-> "", k |-> k]
Idx(a) == CHOOSE i \in 1..Len(ActSeq) : ActSeq[i] = a
InitKey(h) == IF h \in Acts THEN KK(Idx(h)) ELSE DK(h)

VARIABLES ep,     \* epochs: [act, n, par, by, bx, hist, knows, forged];
                  \* a box: [h, key, by (its sealer)]
          rs,     \* re-seal boxes: [e, h, key, by]
          ha,     \* history adds: <<e, f>>: an entry at epoch e carries f
                  \* (held by every node at once: an add is learned like any
                  \* commit, and its order of arrival matters to nothing)
          kn,     \* kn[x]: epoch commits x holds
          krs,    \* krs[x]: re-seal commits x holds
          wr,     \* content: [a, e, w, p1..p5] (p: premises held)
          kg,     \* kg[x]: grants x holds (rule 4)
          pl,     \* removal placements <<dep, label>>
          kpl,    \* kpl[x]: placements x holds
          done,   \* removals made
          evd,    \* Eager pairs, Forgers and HalfForgers used
          nw
vars == <<ep, rs, ha, kn, krs, wr, kg, pl, kpl, done, evd, nw>>
\* the true key holders (every grant held; removed actor edges end theirs),
\* for the properties
KeyAct(a) == KeyIn(GNow(done), a) \cap Acts
KClos(h) == Fix(LAMBDA S : S \cup UNION {KeyAct(b) : b \in S}, KeyAct(h))

Ids == DOMAIN ep
\* made by an honest rotator (not a forgery, not a half-valid rotation)
Honest(e) == ~ep[e].forged /\ ~ep[e].half
\* what e lists, transitively, through honest keysets (ground truth, for
\* the properties)
RECURSIVE AncH(_)
AncH(e) == LET ps == {p \in ep[e].par : Honest(p)} IN ps \cup UNION {AncH(p) : p \in ps}

Known(x) == UNION {ep[e].knows : e \in kn[x]} \cup {p[1] : p \in kpl[x]}
Syncs(x, l) == <<x, l>> \notin NoSync
Vis(x, c) == Syncs(x, c) \/ \E l \in Acts : Syncs(x, l) /\ c \in ActHolders(l)
Through(w, a) == <<w, a>> \in Via
\* x knows w (or an actor w holds directly) left a or an actor holding a
OffPath(x, w, a) == \E dp \in Known(x) : (dp[1] = w \/ (ActDep(dp) /\ w \in Holders(dp[1])))
                                         /\ dp[2] \in HClos(a) \cup {a}
\* a forged keyset is invalid where its forger's removal is known; a rotation
\* by a writer through holder actors where its removal from one is known
Valid(x, k) == /\ ~ep[k].forged \/ ~\E dp \in Known(x) : dp[1] = ep[k].by /\ dp[2] = ep[k].act
               /\ ~(Through(ep[k].by, ep[k].act) /\ OffPath(x, ep[k].by, ep[k].act))
               \* a half-valid rotation where its Authority is judged
               /\ ~(ep[k].half /\ (HalfMode = "keys" \/ (HalfMode = "rotation" /\ Syncs(x, ep[k].act))))
\* what k lists, transitively, through keysets valid at x only (a forged
\* keyset lists every keyset made: descent through it proves nothing)
RECURSIVE AncV(_, _)
AncV(x, k) == LET ps == {p \in ep[k].par : Valid(x, p)} IN ps \cup UNION {AncV(x, p) : p \in ps}
KOf(x, a) == {e \in kn[x] : ep[e].act = a /\ Valid(x, e)}
\* the established ones: a half-valid rotation's epoch is established nowhere
Est(x, a) == {e \in KOf(x, a) : ~ep[e].half}
\* a plain thing x holds no own epoch of: x derives it from its first admin
PlainAt(x, a) == a \in PlainActs /\ KOf(x, a) = {}
Cur(x, a) == {e \in Est(x, a) : ~\E f \in Est(x, a) : e \in AncV(x, f)}
Newer(e, f) == ep[e].n > ep[f].n \/ (ep[e].n = ep[f].n /\ e > f)
Newest(S) == CHOOSE e \in S : \A f \in S \ {e} : Newer(e, f)
NewestV(x, a) == Newest(Cur(x, a))
\* key access over the grants x holds, less actor edges x knows removed
KH(x, a) == KeyIn(kg[x] \ {<<dp[2], dp[1]>> : dp \in {q \in Known(x) : ActDep(q)}}, a)
MemV(x, a, extra) == KH(x, a) \ {dp[1] : dp \in {q \in Known(x) \cup extra : q[2] = a}}

RsBox(r) == [h |-> r.h, key |-> r.key, by |-> r.by]
BoxesAt(x, e) == ep[e].bx \cup {RsBox(r) : r \in {q \in krs[x] : q.e = e}}
AllBoxesAt(e) == ep[e].bx \cup {RsBox(r) : r \in {q \in rs : q.e = e}}

\* epochs whose secret device d gets from boxes BX over commits ids and the
\* history adds H
SecOf(d, BX(_), ids, H) ==
  Fix(LAMBDA S : S \cup {e \in ids : \E b \in BX(e) :
                            (b.key.t = "d" /\ b.key.d = d) \/ (b.key.t = "k" /\ b.key.k \in S)}
                   \cup UNION {ep[f].hist : f \in S \cap ids}
                   \cup {p[2] : p \in {q \in H : q[1] \in S}}, {e \in ids : ep[e].by = d})
Sec(x) == SecOf(x, LAMBDA e : BoxesAt(x, e), kn[x], ha)
ReachD(d) == SecOf(d, AllBoxesAt, Ids, ha)
\* a removed party's devices: a device, or an actor's direct devices
DevsOf(p) == IF p \in Acts THEN Holders(p) \ Acts ELSE {p}
ReachP(p) == UNION {ReachD(d) : d \in DevsOf(p)}
\* the derived secrets of plain thing t at x: its first admin's epochs x
\* holds, and those t's history boxes hand on
DSec(S, t) == {e \in S : ep[e].act = PlainOf(t)} \cup UNION {ep[f].dhist : f \in {g \in S : ep[g].act = t}}
\* content c opens with secrets S
Opens(S, c) == IF c.der THEN c.e \in DSec(S, c.a) ELSE c.e \in S

\* rule 4: an epoch of a boxing an actor with no key access to a (x's view)
Keyless(x, k) == \E b \in BoxesAt(x, k) : b.h \in Acts /\ b.h \notin KH(x, ep[k].act)
StaleK(x, k) == k \in kn[x] /\ (~Valid(x, k) \/ Keyless(x, k)
                                \/ \E j \in KOf(x, ep[k].act) : k \in AncV(x, j))
StaleAt(x, e) == \E b \in BoxesAt(x, e) : b.key.t = "k" /\ StaleK(x, b.key.k)
\* an epoch whose secret x lacks covers nothing (its history box is closed)
Covers(x, e, a) == \A dp \in Known(x) : dp[2] = a => (e \in Sec(x) /\ dp \in ep[e].knows)
IsAdm(x, a) == x \in Learners /\ <<a, x>> \in Adm
\* epochs x may not encrypt under, of those whose secret it holds: missing a
\* departure it knows; for an admin, stale or keyless; boxing an actor at
\* one (sealing there was encrypting under it), any depth: for an admin
\* (Walk "rotator") or for any holder of the secret
Blocked(x) ==
  LET sx == Sec(x)
  IN Fix(LAMBDA S : S \cup {k \in sx : (Walk # "rotator" \/ IsAdm(x, ep[k].act)) /\
                                     \E b \in BoxesAt(x, k) : b.key.t = "k" /\ b.key.k \in S},
         {k \in sx : \/ ~Covers(x, k, ep[k].act)
                     \/ IsAdm(x, ep[k].act) /\ (StaleAt(x, k) \/ Keyless(x, k))})

Anchors(x, a, h) ==
  {k \in Named({b \in UNION {BoxesAt(x, e) : e \in Cur(x, a)} : b.h = h}) :
     k \in kn[x] /\ Valid(x, k)}
\* "mark": the keysets of h a rotation of a left h out at (blocked there),
\* recorded in it, at a's current epochs
OutAt(x, a, h) == {q[2] : q \in {p \in UNION {ep[e].out : e \in Cur(x, a)} : p[1] = h}}
SealSet(x, a, h) ==
  {k \in KOf(x, h) : ~StaleK(x, k) /\
                     (\A q \in Anchors(x, a, h) : q = k \/ q \in AncV(x, k)) /\
                     \A q \in OutAt(x, a, h) : q \in AncV(x, k)}
\* no held valid keyset of h, tainted or not, is or descends from every anchor
Forked(x, a, h) == Anchors(x, a, h) # {} /\ ~\E k \in KOf(x, h) : \A q \in Anchors(x, a, h) : q = k \/ q \in AncV(x, k)
\* the keyset x seals actor h at for a (0: none, h is left out)
SealK(x, a, h) == IF SealSet(x, a, h) = {} THEN 0 ELSE Newest(SealSet(x, a, h))

\* boxes of a to holders hs add blind ones only within MaxBlind
Blinds == UNION {{<<e, b.h>> : b \in {c \in AllBoxesAt(e) : c.h \in Acts \ KeyIn(GNow(done), ep[e].act)}} :
                 e \in Ids}
BlindOK(a, hs) == (hs \cap Acts) \ KeyIn(GNow(done), a) # {} => Cardinality(Blinds) < MaxBlind

\* a rotation of a by x would box an actor whose anchors fork ("wait": or
\* leave out one at a blocked keyset that x may not rotate)
Waits(x, a, extra) == \E h \in MemV(x, a, extra) \cap Acts :
  \/ SealK(x, a, h) = 0 /\ Forked(x, a, h)
  \/ Walk = "wait" /\ SealK(x, a, h) \in Blocked(x) /\ ~(IsAdm(x, h) \/ (Through(x, h) /\ ~OffPath(x, x, h)))

Rotate(x, a, extra, race) ==
  LET lo(h) == h \in Acts /\
               (SealK(x, a, h) = 0 \/ SealK(x, a, h) \in Blocked(x))
      seal(h) == IF h \in Acts THEN KK(SealK(x, a, h)) ELSE DK(h)
      new == [act |-> a,
              n |-> IF Est(x, a) = {} THEN 1 ELSE 1 + ep[NewestV(x, a)].n,
              \* (it lists its current epochs: the established ones)
              par |-> Est(x, a),
              by |-> x,
              bx |-> {[h |-> h, key |-> seal(h), by |-> x] :
                        h \in {g \in MemV(x, a, extra) : ~lo(g)}},
              hist |-> {e \in Sec(x) : ep[e].act = a},
              dhist |-> IF a \in PlainActs THEN DSec(Sec(x), a) ELSE {},
              knows |-> {dp \in Known(x) \cup extra : dp[2] = a},
              forged |-> FALSE, half |-> FALSE,
              race |-> race,
              \* "mark": each actor left out, at its blocked Seal keyset or
              \* the marks it was left out at before
              out |-> IF Walk # "mark" THEN {} ELSE
                      UNION {{<<h, k>> : k \in ({SealK(x, a, h)} \cap Blocked(x)) \cup OutAt(x, a, h)} :
                               h \in {g \in MemV(x, a, extra) : lo(g)}}]
  IN /\ ~Waits(x, a, extra)
     /\ BlindOK(a, {b.h : b \in new.bx})
     /\ ep' = Append(ep, new)
     /\ kn' = [kn EXCEPT ![x] = @ \cup {Len(ep) + 1}]

Init ==
  /\ ep = [i \in 1..Len(ActSeq) |->
             [act |-> ActSeq[i], n |-> 0, par |-> {}, by |-> "",
              bx |-> {[h |-> h, key |-> InitKey(h), by |-> ""] :
                        h \in {g \in KeyIn(GAll, ActSeq[i]) : <<ActSeq[i], g>> \notin GLate}},
              hist |-> {},
              dhist |-> IF ActSeq[i] \in PlainActs THEN {Idx(PlainOf(ActSeq[i]))} ELSE {},
              knows |-> {}, forged |-> FALSE, half |-> FALSE, race |-> FALSE, out |-> {}]]
  /\ rs = {}
  /\ ha = {}
  /\ kn = [x \in Learners |-> {i \in 1..Len(ActSeq) : <<x, ActSeq[i]>> \notin Unaware}]
  /\ krs = [x \in Learners |-> {}]
  /\ wr = {}
  /\ kg = [x \in Learners |-> {g \in GAll : <<x, g>> \notin Hidden}]
  /\ pl = {}
  /\ kpl = [x \in Learners |-> {}]
  /\ done = {}
  /\ evd = {}
  /\ nw = 0

Writer(x, a) == IsAdm(x, a) \/ (x \in Learners /\ Through(x, a) /\ ~OffPath(x, x, a))
\* possession: a writer through holder actors seals one at a keyset it opens
Possess(x, a) == IsAdm(x, a) \/
                 \E h \in ActHolders(a) : SealK(x, a, h) \in Sec(x)

\* y may rotate a, as x sees it
MayRot(x, y, a) == IsAdm(y, a) \/ (y \in Learners /\ Through(y, a) /\ ~OffPath(x, y, a))
\* x merges a fork of a: it made a current epoch other than the newest, or no
\* maker of one may rotate a ("fork": two makers merging alike fork again)
Merger(x, a) ==
  LET others == Cur(x, a) \ {NewestV(x, a)}
  IN (\E f \in others : ep[f].by = x) \/ ~\E f \in others : MayRot(x, ep[f].by, a)
\* rule 3, merge: a current epoch misses a known departure, or there is more
\* than one and x is the merger
MergeDue(x, a) == \/ \E f \in Cur(x, a) : ~Covers(x, f, a)
                  \/ Cardinality(Cur(x, a)) > 1 /\ Merger(x, a)
\* a rotation due for any reason but a fork of knowing epochs: the newest
\* epoch blocked, or any current epoch (held or not) not covering a known
\* departure, with a stale box, or boxing a keyless holder
OtherDue(x, a) ==
  LET e == NewestV(x, a)
  IN \/ e \in Blocked(x)
     \/ \E f \in Cur(x, a) : ~Covers(x, f, a) \/ StaleAt(x, f)
     \/ \E f \in Cur(x, a) : Keyless(x, f)
\* a plain thing given secrets of its own: x wrote it under a derived secret
\* that no history of a current epoch carries (x lacked the own-secrets
\* rotation when it wrote): it is a current epoch beside the own ones, merged
DerivedDue(x, a) == \E c \in wr : c.w = x /\ c.a = a /\ c.der /\
                       c.e \notin UNION {ep[f].dhist : f \in Cur(x, a)}
\* no current secret is needed: any secret of a to wrap the commit under
NeedRot(x, a) ==
  /\ Writer(x, a) /\ Possess(x, a) /\ Est(x, a) # {}
  /\ \E f \in Sec(x) : ep[f].act = a
  /\ OtherDue(x, a) \/ MergeDue(x, a) \/ DerivedDue(x, a)
\* x lacks an epoch of a some node made: a rotation now may fork
Racing(x, a) == \E f \in Ids : ep[f].act = a /\ Honest(f) /\ f \notin kn[x]

Remove(dp) ==
  /\ dp \notin done
  /\ IsAdm(dp[3], dp[2])
  /\ \/ /\ Len(ep) < MaxE
        /\ Rotate(dp[3], dp[2], {dp}, FALSE)
        \* the remover places it under the labels it syncs the removed party
        \* read; placements only judge writers through holder actors (none:
        \* left out, a smaller state space)
        /\ pl' = IF Via = {} THEN pl
                ELSE pl \cup {<<dp, l>> : l \in {l2 \in Acts : dp[2] \in HClos(l2) /\ Syncs(dp[3], l2)}}
        /\ UNCHANGED kpl
     \* written without its rotation (any removal: a superset of the built
     \* cases, a self-removal, Seal waiting, Authority failing), learned under
     \* the actor's label
     \/ /\ pl' = pl \cup {<<dp, dp[2]>>}
        /\ kpl' = [kpl EXCEPT ![dp[3]] = @ \cup {<<dp, dp[2]>>}]
        /\ UNCHANGED <<ep, kn>>
  /\ done' = done \cup {dp}
  /\ UNCHANGED <<kg, rs, krs, ha, wr, evd, nw>>

EagerRot(p) ==
  /\ p \notin evd /\ Len(ep) < MaxE /\ Writer(p[1], p[2]) /\ Possess(p[1], p[2])
  /\ Rotate(p[1], p[2], {}, FALSE)
  /\ evd' = evd \cup {p}
  /\ UNCHANGED <<kg, rs, krs, ha, wr, done, nw, pl, kpl>>

\* a merge of knowing forks alone, racing, only within MaxRace
ForcedRot(x, a) ==
  /\ Len(ep) < MaxE /\ NeedRot(x, a)
  /\ LET race == ~OtherDue(x, a) /\ Racing(x, a)
     IN /\ race => Cardinality({e \in Ids : ep[e].race}) < MaxRace
        /\ Rotate(x, a, {}, race)
  /\ UNCHANGED <<kg, rs, krs, ha, wr, done, evd, nw, pl, kpl>>

Forge(d) ==
  /\ d \in Forgers /\ <<d, "forge">> \notin evd /\ Len(ep) < MaxE
  /\ \E dp \in done :
       /\ dp[1] = d /\ <<dp[2], d>> \in Adm
       /\ LET ms == {e \in Ids : ep[e].act = dp[2] /\ Honest(e)}
          IN ep' = Append(ep, [act |-> dp[2],
                               n |-> 1 + ep[Newest(ms)].n,
                               par |-> ms, by |-> d,
                               bx |-> {[h |-> d, key |-> DK(d), by |-> d]},
                               hist |-> {}, dhist |-> {}, knows |-> {}, forged |-> TRUE, half |-> FALSE, race |-> FALSE, out |-> {}])
  /\ evd' = evd \cup {<<d, "forge">>}
  /\ UNCHANGED <<kg, rs, kn, krs, ha, wr, done, nw, pl, kpl>>

\* q = <<device f, holder actor S, actor M>>: f removes S from M (a self-removal
\* through its admin on S) in one commit with a rotation of M failing Authority
HalfForge(q) ==
  /\ q \in HalfForgers /\ q \notin evd /\ Len(ep) < MaxE
  /\ LET dp == <<q[2], q[3], q[1]>>
         ms == {e \in Ids : ep[e].act = q[3] /\ Honest(e)}
     IN /\ dp \in Deps \ done
        /\ ep' = Append(ep, [act |-> q[3], n |-> 1 + ep[Newest(ms)].n,
                             par |-> ms, by |-> q[1], bx |-> {},
                             hist |-> {}, dhist |-> {}, knows |-> {dp},
                             forged |-> FALSE, half |-> TRUE, race |-> FALSE, out |-> {}])
        /\ done' = done \cup {dp}
  /\ evd' = evd \cup {q}
  /\ UNCHANGED <<kg, rs, kn, krs, ha, wr, nw, pl, kpl>>

\* named keysets come along where x sees their actor (carried)
VisNamed(x, bs) == {k \in Named(bs) : Vis(x, ep[k].act)}

Learn(x, e) ==
  /\ e \in Ids /\ e \notin kn[x] /\ Vis(x, ep[e].act)
  /\ \/ kn' = [kn EXCEPT ![x] = @ \cup {e} \cup VisNamed(x, ep[e].bx)]
     \/ /\ Late
        /\ kn' = [kn EXCEPT ![x] = @ \cup {e}]
     \/ /\ Split /\ \E l \in Acts : Syncs(x, l) /\ ep[e].act \in ActHolders(l)
        /\ kn' = [kn EXCEPT ![x] = @ \cup {e}]
  /\ UNCHANGED <<kg, ep, rs, krs, ha, wr, done, evd, nw, pl, kpl>>

LearnRs(x, r) ==
  /\ r \in rs /\ r \notin krs[x] /\ Vis(x, ep[r.e].act)
  /\ krs' = [krs EXCEPT ![x] = @ \cup {r}]
  /\ kn' = [kn EXCEPT ![x] = @ \cup VisNamed(x, {r})]
  /\ UNCHANGED <<kg, ep, rs, ha, wr, done, evd, nw, pl, kpl>>

LearnG(x, g) ==
  /\ g \in GAll \ kg[x]
  /\ kg' = [kg EXCEPT ![x] = @ \cup {g}]
  /\ UNCHANGED <<ep, rs, kn, krs, ha, wr, done, evd, nw, pl, kpl>>

LearnPl(x, p) ==
  /\ p \in pl /\ p \notin kpl[x] /\ Syncs(x, p[2])
  /\ kpl' = [kpl EXCEPT ![x] = @ \cup {p}]
  /\ UNCHANGED <<kg, ep, rs, kn, krs, ha, wr, done, evd, nw, pl>>

\* x places dp under label l (spec/permissions.md \S 4 Placing revokes: about
\* the author of an entry there)
PlaceOK(x, dp, l) ==
  /\ x # dp[1] /\ Syncs(x, l) /\ dp \in Known(x) /\ dp[2] \in HClos(l)
  /\ <<dp, l>> \notin pl
  /\ \E e \in kn[x] : ep[e].act = l /\ ep[e].by = dp[1]
Place(x, dp, l) ==
  /\ PlaceOK(x, dp, l)
  /\ pl' = pl \cup {<<dp, l>>}
  /\ kpl' = [kpl EXCEPT ![x] = @ \cup {<<dp, l>>}]
  /\ UNCHANGED <<kg, ep, rs, kn, krs, ha, wr, done, evd, nw>>

\* a re-seal of holder h (a device at its key, an actor at its Seal keyset)
Reseal(x, a, h) ==
  /\ Writer(x, a) /\ h \in MemV(x, a, {})
  /\ \E e \in Cur(x, a) \cap Sec(x) :
       /\ CarryFree \/ (Covers(x, e, a) /\ e \notin Blocked(x))
       /\ ~\E b \in BoxesAt(x, e) : b.h = h
       /\ LET k == IF h \in Acts THEN SealK(x, a, h) ELSE 0
              r == [e |-> e, h |-> h, key |-> IF h \in Acts THEN KK(k) ELSE DK(h),
                    by |-> x]
          IN /\ h \in Acts => k # 0 /\ k \notin Blocked(x)
             /\ BlindOK(a, {h})
             /\ rs' = rs \cup {r}
             /\ krs' = [krs EXCEPT ![x] = @ \cup {r}]
  /\ UNCHANGED <<kg, ep, kn, ha, wr, done, evd, nw, pl, kpl>>

\* what the history entries x holds at e list, with the epoch's own
ListedAt(x, e) == ep[e].hist \cup {p[2] : p \in {q \in ha : q[1] = e}}
\* the earlier superseded secrets of e's actor x holds (a current fork's goes
\* by box and merge)
Carry(x, e) == {f \in Sec(x) \ Cur(x, ep[e].act) : ep[e].act = ep[f].act /\ Honest(f) /\ ep[f].n < ep[e].n}
\* x holds an earlier secret no entry at current epoch e (held, not blocked)
\* lists: a history add is due (spec/crypto.md §4, History box)
AddDue(x, a, e) ==
  /\ e \in Cur(x, a) \cap Sec(x) /\ Covers(x, e, a) /\ e \notin Blocked(x)
  /\ ~(Carry(x, e) \subseteq ListedAt(x, e))
HistAdd(x, a, e) ==
  /\ AddDue(x, a, e)
  /\ LET new == {<<e, f>> : f \in Carry(x, e) \ ListedAt(x, e)}
     IN ha' = ha \cup new
  /\ UNCHANGED <<kg, ep, rs, kn, krs, wr, done, evd, nw, pl, kpl>>

\* the inside-member premise: x knows d left M (a holder of a) and holds a
\* keyset of M made knowing it that lists every honest keyset of M made
\* without knowing it
P2Prem(x, a, dp) ==
  /\ dp[2] \in KeyAct(a) /\ dp \in Known(x)
  /\ \A k \in Ids : (ep[k].act = dp[2] /\ Honest(k) /\ dp \notin ep[k].knows) =>
        \E j \in kn[x] : ep[j].act = dp[2] /\ Honest(j) /\ dp \in ep[j].knows /\ k \in AncH(j)

\* removals x knows from a itself or from an actor with no key path to a (a
\* device removed from a true holder is the member limit, p2 and p3)
NotIn(x, a) == {dp \in Known(x) : dp[2] = a \/ dp[2] \notin KClos(a)}

\* the actors on key paths from h up to a, h included
Chain(a, h) == {c \in KClos(a) : c = h \/ h \in KClos(c)}

\* the stated limit at any depth: x holds, for every holder actor h of a, a
\* keyset of h the removed device does not open that lists every honest
\* keyset of h it opens (M's knowing keyset reached x, through h's)
Beaten(x, a, dp) ==
  /\ dp \in done /\ dp[2] \in HClos(a)
  /\ \A h \in KeyAct(a) : \E j \in kn[x] :
        /\ ep[j].act = h /\ Honest(j) /\ j \notin ReachP(dp[1])
        /\ \A k \in Ids : (ep[k].act = h /\ Honest(k) /\ k \in ReachP(dp[1])) => k \in AncH(j)
\* every node holds what it syncs, places what it must and needs no rotation
Settled ==
  /\ \A y \in Learners :
       /\ \A e \in Ids : Vis(y, ep[e].act) => e \in kn[y]
       /\ \A r \in rs : Vis(y, ep[r.e].act) => r \in krs[y]
       /\ \A p \in pl : Syncs(y, p[2]) => p \in kpl[y]
       /\ \A b \in Acts : ~NeedRot(y, b) /\ ~\E e \in Ids : AddDue(y, b, e)
  /\ ~\E y \in Learners, dp \in done, l \in Acts : PlaceOK(y, dp, l)

Write(x, a) ==
  /\ a \in WriteTo /\ Writer(x, a) /\ nw < Writes
  /\ LET der == PlainAt(x, a)
         ea == IF der THEN PlainOf(a) ELSE a
         e == NewestV(x, ea)
     IN /\ e \in Sec(x) /\ Covers(x, e, ea) /\ ~StaleAt(x, e) /\ e \notin Blocked(x)
        /\ ~Keyless(x, e)
        /\ wr' = wr \cup {[a |-> a, e |-> e, w |-> x, der |-> der,
                           p1 |-> {dp \in Known(x) : dp[2] = a},
                           p2 |-> {dp \in Deps : P2Prem(x, a, dp)},
                           p3 |-> IF {r \in rs : r.e = e} \subseteq krs[x]
                                  THEN {dp \in Deps : \A y \in Learners :
                                          IsAdm(y, a) => P2Prem(y, a, dp)}
                                  ELSE {},
                           p4 |-> IF \A y \in Learners : kg[y] = GAll
                                  THEN NotIn(x, a) ELSE {},
                           p5 |-> IF /\ \A y \in Learners : kg[y] = GAll
                                     /\ Ids \subseteq kn[x] /\ rs \subseteq krs[x]
                                  THEN NotIn(x, a) ELSE {},
                           p6 |-> IF {r \in rs : r.e = e} \subseteq krs[x]
                                  THEN {dp \in Deps : dp[1] # x /\ Beaten(x, a, dp)} ELSE {},
                           p7 |-> IF Settled THEN {dp \in done : dp[1] # x /\ dp[2] \in HClos(a)}
                                  ELSE {},
                           p8 |-> IF {r \in rs : r.e = e} \subseteq krs[x]
                                  THEN {dp \in Known(x) : dp[2] \in KClos(a) /\
                                          \A c \in Chain(a, dp[2]) :
                                            {f \in Ids : ep[f].act = c /\ Honest(f)} \subseteq Sec(x)}
                                  ELSE {}]}
  /\ nw' = nw + 1
  /\ UNCHANGED <<kg, ep, rs, kn, krs, ha, done, evd, pl, kpl>>

Next ==
  \/ \E dp \in Deps : Remove(dp)
  \/ \E p \in Eager : EagerRot(p)
  \/ \E d \in Forgers : Forge(d)
  \/ \E q \in HalfForgers : HalfForge(q)
  \/ \E x \in Learners, a \in Acts : ForcedRot(x, a) \/ Write(x, a)
  \/ \E x \in Learners, a \in Acts : \E h \in Holders(a) : Reseal(x, a, h)
  \/ \E x \in Learners, a \in Acts, e \in Ids : HistAdd(x, a, e)
  \/ \E x \in Learners : (\E e \in Ids : Learn(x, e)) \/ (\E r \in rs : LearnRs(x, r))
                          \/ (\E g \in GAll : LearnG(x, g)) \/ (\E p \in pl : LearnPl(x, p))
  \/ \E x \in Learners, dp \in Deps, l \in Acts : Place(x, dp, l)

Fairness ==
  /\ \A x \in Learners : WF_vars((\E e \in Ids : Learn(x, e)) \/ (\E r \in rs : LearnRs(x, r))
                                  \/ (\E g \in GAll : LearnG(x, g)) \/ (\E p \in pl : LearnPl(x, p)))
  /\ \A x \in Learners, a \in Acts : WF_vars(\E e \in Ids : HistAdd(x, a, e))
  /\ \A x \in Learners : WF_vars(\E dp \in Deps, l \in Acts : Place(x, dp, l))
  /\ \A x \in Learners, a \in Acts : WF_vars(ForcedRot(x, a))
  /\ \A x \in Learners, a \in Acts : WF_vars(\E h \in Holders(a) : Reseal(x, a, h))

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---- properties
CurMem(a) == Holders(a) \ {dp[1] : dp \in {q \in done : q[2] = a}}
\* (through key access only: under rule 4 a keyless grant reads nothing)
CurDevs(a) == UNION {CurMem(b) \ Acts : b \in {a} \cup KClos(a)}
\* the reach, for content of a, of removed party p: a device's, or its
\* direct devices' that do not read a now (an actor's devices still read
\* the actor itself and what it holds)
RD(p, a) == IF p \in Acts THEN UNION {ReachD(d) : d \in DevsOf(p) \ CurDevs(a)} ELSE ReachD(p)
GCur(a) == {e \in Ids : ep[e].act = a /\ Honest(e) /\
                        ~\E f \in Ids : Honest(f) /\ e \in AncH(f)}

\* a directly removed holder reads no content written by a writer that knew
NoLeakDirect == \A c \in wr : \A dp \in c.p1 : ~Opens(RD(dp[1], c.a), c)
\* a device removed from a holder actor M of a reads no content of a written
\* by a writer holding M's knowing keyset over every ignorant one
NoLeakMember == \A c \in wr : \A dp \in c.p2 : ~Opens(RD(dp[1], c.a), c)
\* ... where every admin of a held it (the study's "the group's writers")
\* and the writer held every re-seal box of the epoch (an ignorant boxer's
\* box it has not seen is the residual of notes/crypto.md, as today)
NoLeakMemberAll == \A c \in wr : \A dp \in c.p3 : ~Opens(RD(dp[1], c.a), c)
\* rule 4 with a hidden grant, the stated limit: a device removed from a or
\* from an actor with no key path to a reads no content written knowing the
\* removal once every node holds
\* every grant (p4), and the writer also holds every keyset and re-seal (p5)
NoLeakKnown == \A c \in wr : \A dp \in c.p4 : ~Opens(RD(dp[1], c.a), c)
NoLeakKnownAll == \A c \in wr : \A dp \in c.p5 : ~Opens(RD(dp[1], c.a), c)
\* removed-member writer: a device removed from an actor below a reads no
\* content of a written by a writer its removal's knowing keysets reached
\* (the stated limit, Beaten) ...
NoLeakLimit == \A c \in wr : \A dp \in c.p6 : ~Opens(RD(dp[1], c.a), c)
\* ... or at least once every node has settled (the window ends at all)
NoLeakSettled == \A c \in wr : \A dp \in c.p7 : ~Opens(RD(dp[1], c.a), c)
\* a device removed from an actor h below a (any depth) reads no content of a
\* written by a writer that knew the removal and held every epoch of h and of
\* every actor between (and every re-seal box of its epoch), whether or not
\* they have rotated since (Blocked)
NoLeakAbove == \A c \in wr : \A dp \in c.p8 : ~Opens(RD(dp[1], c.a), c)

\* eventually every writer's next epoch is closed to every removed device
\* that no longer reaches the actor (any depth, cycles included)
Excludes == <>[](\A dp \in done : \A a \in Acts : \A x \in Learners : \A d \in DevsOf(dp[1]) :
                   (d \notin CurDevs(a) /\ IsAdm(x, a) /\ Est(x, a) # {}) => NewestV(x, a) \notin ReachD(d))
\* no lockout: every current device of an actor eventually holds every
\* current epoch of it and every epoch content was written under
CurrentOpens == <>[](\A a \in Acts : \A v \in CurDevs(a) \cap Learners :
                       Syncs(v, a) => GCur(a) \subseteq Sec(v))
ReadsAll == <>[](\A c \in wr : \A v \in CurDevs(c.a) \cap Learners : Syncs(v, c.a) => Opens(Sec(v), c))
\* no lockout of a holder actor: every admin of a eventually has a keyset to
\* seal each holder actor with key access at (a rotation of another role
\* would leave it out otherwise: cycle harness seed 1838)
SealsAll == <>[](\A a \in Acts : \A h \in KeyAct(a) : \A x \in Learners :
                   IsAdm(x, a) => SealK(x, a, h) # 0)
\* rotations and history adds stop within MaxE (no ping-pong)
Settles == <>[](\A x \in Learners, a \in Acts : ~NeedRot(x, a) /\ ~\E e \in Ids : AddDue(x, a, e))
=============================================================================

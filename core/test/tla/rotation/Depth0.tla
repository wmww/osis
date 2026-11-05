-------------------------------- MODULE Depth0 --------------------------------
(* Depth-0 sealing (notes/keys-requirements-study.md 2.1, Q2 decided A): a    *)
(* rotation, re-seal or write of actor a never looks inside a holder actor h. *)
(* It seals h at h's newest valid keyset it holds that is or lists every     *)
(* keyset the boxes to h at a's current epochs name (anchors); a box of the   *)
(* epoch it would encrypt under is stale when the keyset it names is invalid *)
(* or listed as superseded by a held valid keyset, and then it rotates first; *)
(* an admin rotates while any current epoch misses a departure it knows      *)
(* (merge). Role cycles (rule 4, issues/keys-depth0.md): no key cycles:      *)
(* actor grants in an agreed order, one closing a cycle over the earlier     *)
(* ones gives no key access, judged over the grants a node holds. Fresh: the *)
(* failed candidate it replaced (leave cycle members out, re-seal by a check *)
(* on their keyset), kept as the record of its counterexample.               *)
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
          Fresh,      \* TRUE: the Fresh candidate instead of rule 4 (a
                      \* rotation leaves cycle member h out, a re-seal seals
                      \* it, unless FreshK holds of its keyset)
          Grants,     \* rule 4: the actor edges of Mem in the agreed order
          Hidden,     \* rule 4: {<<node, edge>>}: grants a node does not
                      \* hold at first (it learns them later)
          MaxBlind,   \* rule 4: bound on blind boxes (to a holder with no
                      \* key access, sealed by a node missing a grant): the
                      \* ignorance window, as one-shot adversary steps
          Taint,      \* rule 4: a keyset boxing a holder without key
                      \* access in the node's view is stale; no stale keyset
                      \* is sealed to
          Via,        \* {<<device, actor>>}: writers of the actor through
                      \* holder actors (rotate, re-seal, write while they do
                      \* not know a removal of theirs from an actor holding it)
          NoSync,     \* {<<node, actor>>}: labels a node does not sync; it
                      \* learns an actor's commits under its own label or a
                      \* target's (keys.0 of a holder), placements under its own
          Split,      \* TRUE: a holder's keys.0 under a target's label
                      \* arrives without the keysets it names (they are
                      \* carried under the holder's own label only)
          Rule        \* removed-member writer (issues/keys-depth0-removed-
                      \* member-rotates.md): "spec" (a reader places a revoke
                      \* about an entry's author), "ahead" (... once it knows
                      \* the removal), "remover" (the remover places under
                      \* every label the actor reaches), "possess" (a writer
                      \* through holder actors rotates only sealing a keyset
                      \* whose secret it holds)

Acts == {ActSeq[i] : i \in 1..Len(ActSeq)}
Holders(a) == {m[2] : m \in {q \in Mem : q[1] = a}}
ActHolders(a) == Holders(a) \cap Acts

Named(bs) == {b.key.k : b \in {c \in bs : c.key.t = "k"}}

RECURSIVE Fix(_, _)
Fix(F(_), S) == LET T == F(S) IN IF T = S THEN S ELSE Fix(F, T)

\* actors holding h, transitively (h itself only on a cycle)
HClos(h) == Fix(LAMBDA S : S \cup UNION {ActHolders(b) : b \in S}, ActHolders(h))
InCycle(a, h) == Fresh /\ a \in HClos(h)

\* rule 4: over edge set E (<<a, h>>: h holds a role on a), the actors whose
\* secrets h's key yields; greedy in the agreed order over the grants G held:
\* a grant whose holder's key a's key already yields gives no key access
GAll == {Grants[i] : i \in 1..Len(Grants)}
\* grants some node lacks at first are made later: initial epochs do not box
\* them, a hidden grant's box is a knowing admin's re-seal
GLate == {q[2] : q \in Hidden}
Yields(E, h) == Fix(LAMBDA S : S \cup {q[1] : q \in {r \in E : r[2] \in S}}, {h})
RECURSIVE KeyedTo(_, _)
KeyedTo(G, i) == IF i = 0 THEN {} ELSE
  LET E == KeyedTo(G, i - 1)
      g == Grants[i]
  IN IF g \in G /\ g[2] \notin Yields(E, g[1]) THEN E \cup {g} ELSE E
\* (a constant table: TLC evaluates it once)
KeyMap == [G \in SUBSET GAll |-> LET E == KeyedTo(G, Len(Grants)) IN
             [a \in Acts |-> IF Fresh THEN Holders(a)
                             ELSE {h \in Holders(a) : h \notin Acts \/ <<a, h>> \in E}]]
KeyIn(G, a) == KeyMap[G][a]
\* the true key holders (every grant held), for the properties
KeyAct(a) == KeyIn(GAll, a) \cap Acts
KClos(h) == Fix(LAMBDA S : S \cup UNION {KeyAct(b) : b \in S}, KeyAct(h))

DK(d) == [t |-> "d", d |-> d, k |-> 0]
KK(k) == [t |-> "k", d |-> "", k |-> k]
Idx(a) == CHOOSE i \in 1..Len(ActSeq) : ActSeq[i] = a
InitKey(h) == IF h \in Acts THEN KK(Idx(h)) ELSE DK(h)

VARIABLES ep,     \* epochs: [act, n, par, by, bx, hist, knows, forged]
          rs,     \* re-seal boxes: [e, h, key]
          kn,     \* kn[x]: epoch commits x holds
          krs,    \* krs[x]: re-seal commits x holds
          wr,     \* content: [a, e, w, p1..p5] (p: premises held)
          kg,     \* kg[x]: grants x holds (rule 4)
          pl,     \* removal placements <<dep, label>>
          kpl,    \* kpl[x]: placements x holds
          done,   \* removals made
          evd,    \* Eager pairs and Forgers used
          nw
vars == <<ep, rs, kn, krs, wr, kg, pl, kpl, done, evd, nw>>

Ids == DOMAIN ep
\* what e lists, transitively, through honest keysets (ground truth, for
\* the properties)
RECURSIVE AncH(_)
AncH(e) == LET ps == {p \in ep[e].par : ~ep[p].forged} IN ps \cup UNION {AncH(p) : p \in ps}

Known(x) == UNION {ep[e].knows : e \in kn[x]} \cup {p[1] : p \in kpl[x]}
Syncs(x, l) == <<x, l>> \notin NoSync
Vis(x, c) == Syncs(x, c) \/ \E l \in Acts : Syncs(x, l) /\ c \in ActHolders(l)
Through(w, a) == <<w, a>> \in Via
\* x knows w left an actor holding a
OffPath(x, w, a) == \E dp \in Known(x) : dp[1] = w /\ dp[2] \in HClos(a)
\* a forged keyset is invalid where its forger's removal is known; a rotation
\* by a writer through holder actors where its removal from one is known
Valid(x, k) == /\ ~ep[k].forged \/ ~\E dp \in Known(x) : dp[1] = ep[k].by /\ dp[2] = ep[k].act
               /\ ~(Through(ep[k].by, ep[k].act) /\ OffPath(x, ep[k].by, ep[k].act))
\* what k lists, transitively, through keysets valid at x only (a forged
\* keyset lists every keyset made: descent through it proves nothing)
RECURSIVE AncV(_, _)
AncV(x, k) == LET ps == {p \in ep[k].par : Valid(x, p)} IN ps \cup UNION {AncV(x, p) : p \in ps}
KOf(x, a) == {e \in kn[x] : ep[e].act = a /\ Valid(x, e)}
Cur(x, a) == {e \in KOf(x, a) : ~\E f \in KOf(x, a) : e \in AncV(x, f)}
Newer(e, f) == ep[e].n > ep[f].n \/ (ep[e].n = ep[f].n /\ e > f)
Newest(S) == CHOOSE e \in S : \A f \in S \ {e} : Newer(e, f)
NewestV(x, a) == Newest(Cur(x, a))
KH(x, a) == KeyIn(kg[x], a)
MemV(x, a, extra) == KH(x, a) \ {dp[1] : dp \in {q \in Known(x) \cup extra : q[2] = a}}

BoxesAt(x, e) == ep[e].bx \cup {[h |-> r.h, key |-> r.key] : r \in {q \in krs[x] : q.e = e}}
AllBoxesAt(e) == ep[e].bx \cup {[h |-> r.h, key |-> r.key] : r \in {q \in rs : q.e = e}}

\* epochs whose secret device d gets from boxes BX over commits ids
SecOf(d, BX(_), ids) ==
  Fix(LAMBDA S : S \cup {e \in ids : \E b \in BX(e) :
                            (b.key.t = "d" /\ b.key.d = d) \/ (b.key.t = "k" /\ b.key.k \in S)}
                   \cup UNION {ep[f].hist : f \in S \cap ids}, {e \in ids : ep[e].by = d})
Sec(x) == SecOf(x, LAMBDA e : BoxesAt(x, e), kn[x])
ReachD(d) == SecOf(d, AllBoxesAt, Ids)

\* rule 4: an epoch of a boxing an actor with no key access to a (x's view)
Keyless(x, k) == \E b \in BoxesAt(x, k) : b.h \in Acts /\ b.h \notin KH(x, ep[k].act)
StaleK(x, k) == k \in kn[x] /\ (~Valid(x, k) \/ (Taint /\ Keyless(x, k))
                                \/ \E j \in KOf(x, ep[k].act) : k \in AncV(x, j))
StaleAt(x, e) == \E b \in BoxesAt(x, e) : b.key.t = "k" /\ StaleK(x, b.key.k)
Covers(x, e, a) == \A dp \in Known(x) : dp[2] = a => dp \in ep[e].knows

\* Fresh (fails with two admins of h, D0_cyc_2adm_fresh): k's boxes to a
\* name only current keysets of a, and, if it has none (a node of h would
\* re-seal k to its newest keyset of a), no superseded epoch of a boxes h at
\* k (an ignorant node of h would take that epoch for a's newest and re-seal
\* k to it)
FreshK(x, a, k, cur, old) ==
  /\ \A b \in BoxesAt(x, k) : b.h = a => (b.key.t = "k" /\ b.key.k \in cur)
  /\ \/ \E b \in BoxesAt(x, k) : b.h = a
     \/ ~\E e \in old : \E b \in BoxesAt(x, e) : b.h = ep[k].act /\ b.key = KK(k)

Anchors(x, a, h) ==
  {k \in Named({b \in UNION {BoxesAt(x, e) : e \in Cur(x, a)} : b.h = h}) :
     k \in kn[x] /\ Valid(x, k)}
SealSet(x, a, h) ==
  {k \in KOf(x, h) : ~(Taint /\ StaleK(x, k)) /\
                     \A q \in Anchors(x, a, h) : q = k \/ q \in AncV(x, k)}
\* the keyset x seals actor h at for a (0: none, h is left out)
SealK(x, a, h) == IF SealSet(x, a, h) = {} THEN 0 ELSE Newest(SealSet(x, a, h))

\* boxes of a to holders hs add blind ones only within MaxBlind
Blinds == UNION {{<<e, b.h>> : b \in {c \in AllBoxesAt(e) : c.h \in Acts \ KeyIn(GAll, ep[e].act)}} :
                 e \in Ids}
BlindOK(a, hs) == (hs \cap Acts) \ KeyIn(GAll, a) # {} => Cardinality(Blinds) < MaxBlind

Rotate(x, a, extra) ==
  LET lo(h) == h \in Acts /\
               (SealK(x, a, h) = 0 \/
                (InCycle(a, h) /\ ~FreshK(x, a, SealK(x, a, h), {}, KOf(x, a))))
      seal(h) == IF h \in Acts THEN KK(SealK(x, a, h)) ELSE DK(h)
      new == [act |-> a,
              n |-> 1 + ep[NewestV(x, a)].n,
              par |-> KOf(x, a),
              by |-> x,
              bx |-> {[h |-> h, key |-> seal(h)] : h \in {g \in MemV(x, a, extra) : ~lo(g)}},
              hist |-> {e \in Sec(x) : ep[e].act = a},
              knows |-> {dp \in Known(x) \cup extra : dp[2] = a},
              forged |-> FALSE]
  IN /\ BlindOK(a, {b.h : b \in new.bx})
     /\ ep' = Append(ep, new)
     /\ kn' = [kn EXCEPT ![x] = @ \cup {Len(ep) + 1}]

Init ==
  /\ ep = [i \in 1..Len(ActSeq) |->
             [act |-> ActSeq[i], n |-> 0, par |-> {}, by |-> "",
              bx |-> {[h |-> h, key |-> InitKey(h)] :
                        h \in {g \in KeyIn(GAll, ActSeq[i]) : <<ActSeq[i], g>> \notin GLate}},
              hist |-> {}, knows |-> {}, forged |-> FALSE]]
  /\ rs = {}
  /\ kn = [x \in Learners |-> 1..Len(ActSeq)]
  /\ krs = [x \in Learners |-> {}]
  /\ wr = {}
  /\ kg = [x \in Learners |-> {g \in GAll : <<x, g>> \notin Hidden}]
  /\ pl = {}
  /\ kpl = [x \in Learners |-> {}]
  /\ done = {}
  /\ evd = {}
  /\ nw = 0

IsAdm(x, a) == x \in Learners /\ <<a, x>> \in Adm
Writer(x, a) == IsAdm(x, a) \/ (x \in Learners /\ Through(x, a) /\ ~OffPath(x, x, a))
\* "possess": a writer through holder actors seals one at a keyset it opens
Possess(x, a) == Rule # "possess" \/ IsAdm(x, a) \/
                 \E h \in ActHolders(a) : SealK(x, a, h) \in Sec(x)

NeedRot(x, a) ==
  /\ Writer(x, a) /\ Possess(x, a)
  /\ LET e == NewestV(x, a)
     IN /\ e \in Sec(x)
        /\ \/ ~Covers(x, e, a) \/ StaleAt(x, e)
           \/ \E f \in Cur(x, a) : ~Covers(x, f, a)
           \/ ~Fresh /\ \E f \in Cur(x, a) : Keyless(x, f)

Remove(dp) ==
  /\ dp \notin done /\ Len(ep) < MaxE
  /\ IsAdm(dp[3], dp[2])
  /\ Rotate(dp[3], dp[2], {dp})
  /\ done' = done \cup {dp}
  \* the remover places it under the labels it syncs the removed party read
  \* ("remover": every label the actor reaches); placements only judge
  \* writers through holder actors (none: left out, a smaller state space)
  /\ pl' = IF Via = {} THEN pl
          ELSE pl \cup {<<dp, l>> : l \in {l2 \in Acts : dp[2] \in HClos(l2) /\
                                           (Rule = "remover" \/ Syncs(dp[3], l2))}}
  /\ UNCHANGED <<kg, rs, krs, wr, evd, nw, kpl>>

EagerRot(p) ==
  /\ p \notin evd /\ Len(ep) < MaxE /\ Writer(p[1], p[2]) /\ Possess(p[1], p[2])
  /\ Rotate(p[1], p[2], {})
  /\ evd' = evd \cup {p}
  /\ UNCHANGED <<kg, rs, krs, wr, done, nw, pl, kpl>>

ForcedRot(x, a) ==
  /\ Len(ep) < MaxE /\ NeedRot(x, a)
  /\ Rotate(x, a, {})
  /\ UNCHANGED <<kg, rs, krs, wr, done, evd, nw, pl, kpl>>

Forge(d) ==
  /\ d \in Forgers /\ <<d, "forge">> \notin evd /\ Len(ep) < MaxE
  /\ \E dp \in done :
       /\ dp[1] = d /\ <<dp[2], d>> \in Adm
       /\ LET ms == {e \in Ids : ep[e].act = dp[2] /\ ~ep[e].forged}
          IN ep' = Append(ep, [act |-> dp[2],
                               n |-> 1 + ep[Newest(ms)].n,
                               par |-> ms, by |-> d,
                               bx |-> {[h |-> d, key |-> DK(d)]},
                               hist |-> {}, knows |-> {}, forged |-> TRUE])
  /\ evd' = evd \cup {<<d, "forge">>}
  /\ UNCHANGED <<kg, rs, kn, krs, wr, done, nw, pl, kpl>>

\* named keysets come along where x sees their actor (carried)
VisNamed(x, bs) == {k \in Named(bs) : Vis(x, ep[k].act)}

Learn(x, e) ==
  /\ e \in Ids /\ e \notin kn[x] /\ Vis(x, ep[e].act)
  /\ \/ kn' = [kn EXCEPT ![x] = @ \cup {e} \cup VisNamed(x, ep[e].bx)]
     \/ /\ Split /\ \E l \in Acts : Syncs(x, l) /\ ep[e].act \in ActHolders(l)
        /\ kn' = [kn EXCEPT ![x] = @ \cup {e}]
  /\ UNCHANGED <<kg, ep, rs, krs, wr, done, evd, nw, pl, kpl>>

LearnRs(x, r) ==
  /\ r \in rs /\ r \notin krs[x] /\ Vis(x, ep[r.e].act)
  /\ krs' = [krs EXCEPT ![x] = @ \cup {r}]
  /\ kn' = [kn EXCEPT ![x] = @ \cup VisNamed(x, {r})]
  /\ UNCHANGED <<kg, ep, rs, wr, done, evd, nw, pl, kpl>>

LearnG(x, g) ==
  /\ g \in GAll \ kg[x]
  /\ kg' = [kg EXCEPT ![x] = @ \cup {g}]
  /\ UNCHANGED <<ep, rs, kn, krs, wr, done, evd, nw, pl, kpl>>

LearnPl(x, p) ==
  /\ p \in pl /\ p \notin kpl[x] /\ Syncs(x, p[2])
  /\ kpl' = [kpl EXCEPT ![x] = @ \cup {p}]
  /\ UNCHANGED <<kg, ep, rs, kn, krs, wr, done, evd, nw, pl>>

\* x places dp under label l (spec/permissions.md \S 4 Placing revokes: about
\* the author of an entry there; "ahead": once x knows it)
PlaceOK(x, dp, l) ==
  /\ x # dp[1] /\ Syncs(x, l) /\ dp \in Known(x) /\ dp[2] \in HClos(l)
  /\ <<dp, l>> \notin pl
  /\ Rule = "ahead" \/ \E e \in kn[x] : ep[e].act = l /\ ep[e].by = dp[1]
Place(x, dp, l) ==
  /\ PlaceOK(x, dp, l)
  /\ pl' = pl \cup {<<dp, l>>}
  /\ kpl' = [kpl EXCEPT ![x] = @ \cup {<<dp, l>>}]
  /\ UNCHANGED <<kg, ep, rs, kn, krs, wr, done, evd, nw>>

Reseal(x, a, h) ==
  /\ Writer(x, a) /\ h \in MemV(x, a, {}) \cap Acts
  /\ \E e \in Cur(x, a) \cap Sec(x) :
       /\ Covers(x, e, a)
       /\ ~\E b \in BoxesAt(x, e) : b.h = h
       /\ LET k == SealK(x, a, h)
              r == [e |-> e, h |-> h, key |-> KK(k)]
          IN /\ k # 0
             \* "possess": a writer through holder actors re-seals one only at a keyset it opens
             /\ (Rule = "possess" /\ Through(x, a) /\ ~IsAdm(x, a)) => k \in Sec(x)
             /\ InCycle(a, h) => FreshK(x, a, k, Cur(x, a), KOf(x, a) \ Cur(x, a))
             /\ BlindOK(a, {h})
             /\ rs' = rs \cup {r}
             /\ krs' = [krs EXCEPT ![x] = @ \cup {r}]
  /\ UNCHANGED <<kg, ep, kn, wr, done, evd, nw, pl, kpl>>

\* the inside-member premise: x knows d left M (a holder of a) and holds a
\* keyset of M made knowing it that lists every honest keyset of M made
\* without knowing it
P2Prem(x, a, dp) ==
  /\ dp[2] \in KeyAct(a) /\ dp \in Known(x)
  /\ \A k \in Ids : (ep[k].act = dp[2] /\ ~ep[k].forged /\ dp \notin ep[k].knows) =>
        \E j \in kn[x] : ep[j].act = dp[2] /\ ~ep[j].forged /\ dp \in ep[j].knows /\ k \in AncH(j)

\* removals x knows from a itself or from an actor with no key path to a (a
\* device removed from a true holder is the member limit, p2 and p3)
NotIn(x, a) == {dp \in Known(x) : dp[2] = a \/ dp[2] \notin KClos(a)}

\* the stated limit at any depth: x holds, for every holder actor h of a, a
\* keyset of h the removed device does not open that lists every honest
\* keyset of h it opens (M's knowing keyset reached x, through h's)
Beaten(x, a, dp) ==
  /\ dp \in done /\ dp[2] \in HClos(a)
  /\ \A h \in KeyAct(a) : \E j \in kn[x] :
        /\ ep[j].act = h /\ ~ep[j].forged /\ j \notin ReachD(dp[1])
        /\ \A k \in Ids : (ep[k].act = h /\ ~ep[k].forged /\ k \in ReachD(dp[1])) => k \in AncH(j)
\* every node holds what it syncs, places what it must and needs no rotation
Settled ==
  /\ \A y \in Learners :
       /\ \A e \in Ids : Vis(y, ep[e].act) => e \in kn[y]
       /\ \A r \in rs : Vis(y, ep[r.e].act) => r \in krs[y]
       /\ \A p \in pl : Syncs(y, p[2]) => p \in kpl[y]
       /\ \A b \in Acts : ~NeedRot(y, b)
  /\ ~\E y \in Learners, dp \in done, l \in Acts : PlaceOK(y, dp, l)

Write(x, a) ==
  /\ a \in WriteTo /\ Writer(x, a) /\ nw < Writes
  /\ LET e == NewestV(x, a)
     IN /\ e \in Sec(x) /\ Covers(x, e, a) /\ ~StaleAt(x, e)
        /\ ~(~Fresh /\ Keyless(x, e))
        /\ wr' = wr \cup {[a |-> a, e |-> e, w |-> x,
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
                                  ELSE {}]}
  /\ nw' = nw + 1
  /\ UNCHANGED <<kg, ep, rs, kn, krs, done, evd, pl, kpl>>

Next ==
  \/ \E dp \in Deps : Remove(dp)
  \/ \E p \in Eager : EagerRot(p)
  \/ \E d \in Forgers : Forge(d)
  \/ \E x \in Learners, a \in Acts : ForcedRot(x, a) \/ Write(x, a)
  \/ \E x \in Learners, a \in Acts, h \in Acts : Reseal(x, a, h)
  \/ \E x \in Learners : (\E e \in Ids : Learn(x, e)) \/ (\E r \in rs : LearnRs(x, r))
                          \/ (\E g \in GAll : LearnG(x, g)) \/ (\E p \in pl : LearnPl(x, p))
  \/ \E x \in Learners, dp \in Deps, l \in Acts : Place(x, dp, l)

Fairness ==
  /\ \A x \in Learners : WF_vars((\E e \in Ids : Learn(x, e)) \/ (\E r \in rs : LearnRs(x, r))
                                  \/ (\E g \in GAll : LearnG(x, g)) \/ (\E p \in pl : LearnPl(x, p)))
  /\ \A x \in Learners : WF_vars(\E dp \in Deps, l \in Acts : Place(x, dp, l))
  /\ \A x \in Learners, a \in Acts : WF_vars(ForcedRot(x, a))
  /\ \A x \in Learners, a \in Acts : WF_vars(\E h \in Acts : Reseal(x, a, h))

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---- properties
CurMem(a) == Holders(a) \ {dp[1] : dp \in {q \in done : q[2] = a}}
\* (through key access only: under rule 4 a keyless grant reads nothing)
CurDevs(a) == UNION {CurMem(b) \ Acts : b \in {a} \cup KClos(a)}
GCur(a) == {e \in Ids : ep[e].act = a /\ ~ep[e].forged /\
                        ~\E f \in Ids : ~ep[f].forged /\ e \in AncH(f)}

\* a directly removed holder reads no content written by a writer that knew
NoLeakDirect == \A c \in wr : \A dp \in c.p1 : c.e \notin ReachD(dp[1])
\* a device removed from a holder actor M of a reads no content of a written
\* by a writer holding M's knowing keyset over every ignorant one
NoLeakMember == \A c \in wr : \A dp \in c.p2 : c.e \notin ReachD(dp[1])
\* ... where every admin of a held it (the study's "the group's writers")
\* and the writer held every re-seal box of the epoch (an ignorant boxer's
\* box it has not seen is the residual of notes/crypto.md, as today)
NoLeakMemberAll == \A c \in wr : \A dp \in c.p3 : c.e \notin ReachD(dp[1])
\* rule 4 with a hidden grant, the stated limit: a device removed from a or
\* from an actor with no key path to a reads no content written knowing the
\* removal once every node holds
\* every grant (p4), and the writer also holds every keyset and re-seal (p5)
NoLeakKnown == \A c \in wr : \A dp \in c.p4 : c.e \notin ReachD(dp[1])
NoLeakKnownAll == \A c \in wr : \A dp \in c.p5 : c.e \notin ReachD(dp[1])
\* removed-member writer: a device removed from an actor below a reads no
\* content of a written by a writer its removal's knowing keysets reached
\* (the stated limit, Beaten) ...
NoLeakLimit == \A c \in wr : \A dp \in c.p6 : c.e \notin ReachD(dp[1])
\* ... or at least once every node has settled (the window ends at all)
NoLeakSettled == \A c \in wr : \A dp \in c.p7 : c.e \notin ReachD(dp[1])

\* eventually every writer's next epoch is closed to every removed device
\* that no longer reaches the actor (any depth, cycles included)
Excludes == <>[](\A dp \in done : \A a \in Acts : \A x \in Learners :
                   (dp[1] \notin CurDevs(a) /\ IsAdm(x, a)) => NewestV(x, a) \notin ReachD(dp[1]))
\* no lockout: every current device of an actor eventually holds every
\* current epoch of it and every epoch content was written under
CurrentOpens == <>[](\A a \in Acts : \A v \in CurDevs(a) \cap Learners :
                       Syncs(v, a) => GCur(a) \subseteq Sec(v))
ReadsAll == <>[](\A c \in wr : \A v \in CurDevs(c.a) \cap Learners : Syncs(v, c.a) => c.e \in Sec(v))
\* rotations stop within MaxE (no ping-pong)
Settles == <>[](\A x \in Learners, a \in Acts : ~NeedRot(x, a))
=============================================================================

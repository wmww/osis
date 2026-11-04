-------------------------------- MODULE Depth0 --------------------------------
(* Depth-0 sealing (notes/keys-requirements-study.md 2.1, Q2 decided A): a    *)
(* rotation, re-seal or write of actor a never looks inside a holder actor h. *)
(* It seals h at h's newest valid keyset it holds; a box of the epoch it would *)
(* encrypt under is stale when the keyset it names is invalid or listed as    *)
(* superseded by a held valid keyset, and then it rotates first. Role cycles: *)
(* a rotation leaves out holder actors whose holder closure contains a, and   *)
(* re-seals them once a check on their keyset passes (CycleCheck, variants). *)
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
          LeaveOut,   \* which rotations leave a cycle member h out (no
                      \* candidate is sound and live, notes/keys-requirements-
                      \* study.md 4): "direct" those carrying or forced by a
                      \* direct departure (the study's text); "all" every
                      \* rotation; "noback" iff h's keyset holds a box to a;
                      \* "fresh" unless Fresh with nothing current; "commit"
                      \* unless RotOK
          CycleCheck, \* when a re-seal may seal cycle member h at keyset k:
                      \* "box" k has a box to a naming a current keyset of a
                      \* (the study's one box check); "reach" k is not
                      \* reachable from a's superseded keysets over the boxes
                      \* the node holds; "fresh" Fresh; "commit" ResealOK
          Stale,      \* a box to h at keyset k is stale where k is invalid or
                      \* "listed": a held valid keyset of h lists k (the
                      \* study's rule); "newer": one is newer than k by (n, id)
          Anchor,     \* TRUE: seal h only at a keyset that is or lists every
                      \* valid keyset of h the boxes to h at a's current
                      \* epochs name (none: leave h out)
          Merge,      \* TRUE: an admin rotates while any current epoch (not
                      \* only the newest) misses a departure it knows
          Rejoin,     \* TRUE: an admin of a rotates while a cycle member is
                      \* missing from its newest epoch and the keyset it
                      \* would seal it at holds no box to a
          Carry       \* learning a commit teaches the keysets its boxes name
                      \* (the holder's keys.0 under the target's label)

Acts == {ActSeq[i] : i \in 1..Len(ActSeq)}
Holders(a) == {m[2] : m \in {q \in Mem : q[1] = a}}
ActHolders(a) == Holders(a) \cap Acts
Devices == UNION {Holders(a) : a \in Acts} \ Acts

Named(bs) == {b.key.k : b \in {c \in bs : c.key.t = "k"}}

RECURSIVE Fix(_, _)
Fix(F(_), S) == LET T == F(S) IN IF T = S THEN S ELSE Fix(F, T)

\* actors holding h, transitively (h itself only on a cycle)
HClos(h) == Fix(LAMBDA S : S \cup UNION {ActHolders(b) : b \in S}, ActHolders(h))
InCycle(a, h) == a \in HClos(h)

DK(d) == [t |-> "d", d |-> d, k |-> 0]
KK(k) == [t |-> "k", d |-> "", k |-> k]
Idx(a) == CHOOSE i \in 1..Len(ActSeq) : ActSeq[i] = a
InitKey(h) == IF h \in Acts THEN KK(Idx(h)) ELSE DK(h)

VARIABLES ep,     \* epochs: [act, n, par, by, bx, hist, knows, forged]
          rs,     \* re-seal boxes: [e, h, key]
          kn,     \* kn[x]: epoch commits x holds
          krs,    \* krs[x]: re-seal commits x holds
          wr,     \* content: [a, e, w, p1, p2, p3] (p: premises held)
          done,   \* removals made
          evd,    \* Eager pairs and Forgers used
          nw
vars == <<ep, rs, kn, krs, wr, done, evd, nw>>

Ids == DOMAIN ep
\* what e lists, transitively, through honest keysets (ground truth, for
\* the properties)
RECURSIVE AncH(_)
AncH(e) == LET ps == {p \in ep[e].par : ~ep[p].forged} IN ps \cup UNION {AncH(p) : p \in ps}

Known(x) == UNION {ep[e].knows : e \in kn[x]}
\* a forged keyset is invalid where its forger's removal is known
Valid(x, k) == ~ep[k].forged \/ ~\E dp \in Known(x) : dp[1] = ep[k].by /\ dp[2] = ep[k].act
\* what k lists, transitively, through keysets valid at x only (a forged
\* keyset lists every keyset made: descent through it proves nothing)
RECURSIVE AncV(_, _)
AncV(x, k) == LET ps == {p \in ep[k].par : Valid(x, p)} IN ps \cup UNION {AncV(x, p) : p \in ps}
KOf(x, a) == {e \in kn[x] : ep[e].act = a /\ Valid(x, e)}
Cur(x, a) == {e \in KOf(x, a) : ~\E f \in KOf(x, a) : e \in AncV(x, f)}
Newer(e, f) == ep[e].n > ep[f].n \/ (ep[e].n = ep[f].n /\ e > f)
Newest(S) == CHOOSE e \in S : \A f \in S \ {e} : Newer(e, f)
NewestV(x, a) == Newest(Cur(x, a))
MemV(x, a, extra) == Holders(a) \ {dp[1] : dp \in {q \in Known(x) \cup extra : q[2] = a}}

BoxesAt(x, e) == ep[e].bx \cup {[h |-> r.h, key |-> r.key] : r \in {q \in krs[x] : q.e = e}}
AllBoxesAt(e) == ep[e].bx \cup {[h |-> r.h, key |-> r.key] : r \in {q \in rs : q.e = e}}

\* epochs whose secret device d gets from boxes BX over commits ids
SecOf(d, BX(_), ids) ==
  Fix(LAMBDA S : S \cup {e \in ids : \E b \in BX(e) :
                            (b.key.t = "d" /\ b.key.d = d) \/ (b.key.t = "k" /\ b.key.k \in S)}
                   \cup UNION {ep[f].hist : f \in S \cap ids}, {})
Sec(x) == SecOf(x, LAMBDA e : BoxesAt(x, e), kn[x])
ReachD(d) == SecOf(d, AllBoxesAt, Ids)

StaleK(x, k) == k \in kn[x] /\ (~Valid(x, k) \/ \E j \in KOf(x, ep[k].act) :
                    IF Stale = "listed" THEN k \in AncV(x, j) ELSE Newer(j, k))
StaleAt(x, e) == \E b \in BoxesAt(x, e) : b.key.t = "k" /\ StaleK(x, b.key.k)
Covers(x, e, a) == \A dp \in Known(x) : dp[2] = a => dp \in ep[e].knows

\* epochs reachable, in x's view, from the secrets of old (keyset names x
\* holds no commit of count as reached: their boxes are unknown)
ViewReach(x, old) ==
  LET named == {b.key.k : b \in {c \in UNION {BoxesAt(x, e) : e \in kn[x]} : c.key.t = "k"}}
  IN Fix(LAMBDA S : S \cup {e \in kn[x] : \E b \in BoxesAt(x, e) : b.key.t = "k" /\ b.key.k \in S}
                      \cup UNION {ep[f].hist : f \in S \cap kn[x]},
         old \cup (named \ kn[x]))
BackBox(x, a, k) == \E b \in BoxesAt(x, k) : b.h = a

\* (fails with two admins of h, D0_cyc_2adm_fresh) k's boxes to a name
\* only current keysets of a, and, if it has none (a
\* node of h would re-seal k to its newest keyset of a), no superseded epoch
\* of a boxes h at k (an ignorant node of h would take that epoch for a's
\* newest and re-seal k to it)
Fresh(x, a, k, cur, old) ==
  /\ \A b \in BoxesAt(x, k) : b.h = a => (b.key.t = "k" /\ b.key.k \in cur)
  /\ BackBox(x, a, k) \/ ~\E e \in old : \E b \in BoxesAt(x, e) : b.h = ep[k].act /\ b.key = KK(k)
\* Commit rule: a rotation seals cycle member h at k only when k
\* holds no box to a and no epoch of a boxes h at k (all of them are
\* superseded by it); a re-seal only when k's own rotation commit boxes a at
\* a current keyset of a and every box of k to a it holds does (re-seal boxes
\* of k may exist unseen; its commit's boxes travel with k)
RotOK(x, a, k) ==
  /\ ~BackBox(x, a, k)
  /\ ~\E e \in KOf(x, a) : \E b \in BoxesAt(x, e) : b.h = ep[k].act /\ b.key = KK(k)
ResealOK(x, a, k, cur) ==
  /\ \E b \in ep[k].bx : b.h = a /\ b.key.t = "k" /\ b.key.k \in cur
  /\ \A b \in BoxesAt(x, k) : b.h = a => (b.key.t = "k" /\ b.key.k \in cur)
\* may x seal a to cycle member keyset k, a's current keysets cur, old ones old
CC(x, a, k, cur, old) ==
  CASE CycleCheck = "box" ->
         \E b \in BoxesAt(x, k) : b.h = a /\ b.key.t = "k" /\ b.key.k \in cur
    [] CycleCheck = "reach" -> k \notin ViewReach(x, old)
    [] CycleCheck = "fresh" -> Fresh(x, a, k, cur, old)
    [] CycleCheck = "commit" -> ResealOK(x, a, k, cur)

Anchors(x, a, h) ==
  {k \in Named({b \in UNION {BoxesAt(x, e) : e \in Cur(x, a)} : b.h = h}) :
     k \in kn[x] /\ Valid(x, k)}
SealSet(x, a, h) ==
  {k \in KOf(x, h) : Anchor => \A q \in Anchors(x, a, h) : q = k \/ q \in AncV(x, k)}
\* the keyset x seals actor h at for a (0: none, h is left out)
SealK(x, a, h) == IF SealSet(x, a, h) = {} THEN 0 ELSE Newest(SealSet(x, a, h))

Rotate(x, a, extra, dir) ==
  LET lo(h) == h \in Acts /\
               (SealK(x, a, h) = 0 \/
                (InCycle(a, h) /\
                 CASE LeaveOut = "direct" -> dir
                   [] LeaveOut = "all" -> TRUE
                   [] LeaveOut = "noback" -> BackBox(x, a, SealK(x, a, h))
                   [] LeaveOut = "fresh" -> ~Fresh(x, a, SealK(x, a, h), {}, KOf(x, a))
                   [] LeaveOut = "commit" -> ~RotOK(x, a, SealK(x, a, h))))
      seal(h) == IF h \in Acts THEN KK(SealK(x, a, h)) ELSE DK(h)
      new == [act |-> a,
              n |-> 1 + ep[NewestV(x, a)].n,
              par |-> KOf(x, a),
              by |-> x,
              bx |-> {[h |-> h, key |-> seal(h)] : h \in {g \in MemV(x, a, extra) : ~lo(g)}},
              hist |-> {e \in Sec(x) : ep[e].act = a},
              knows |-> Known(x) \cup extra,
              forged |-> FALSE]
  IN /\ ep' = Append(ep, new)
     /\ kn' = [kn EXCEPT ![x] = @ \cup {Len(ep) + 1}]

Init ==
  /\ ep = [i \in 1..Len(ActSeq) |->
             [act |-> ActSeq[i], n |-> 0, par |-> {}, by |-> "",
              bx |-> {[h |-> h, key |-> InitKey(h)] : h \in Holders(ActSeq[i])},
              hist |-> {}, knows |-> {}, forged |-> FALSE]]
  /\ rs = {}
  /\ kn = [x \in Learners |-> 1..Len(ActSeq)]
  /\ krs = [x \in Learners |-> {}]
  /\ wr = {}
  /\ done = {}
  /\ evd = {}
  /\ nw = 0

IsAdm(x, a) == x \in Learners /\ <<a, x>> \in Adm

NeedRot(x, a) ==
  /\ IsAdm(x, a)
  /\ LET e == NewestV(x, a)
     IN /\ e \in Sec(x)
        /\ \/ ~Covers(x, e, a) \/ StaleAt(x, e)
           \/ Merge /\ \E f \in Cur(x, a) : ~Covers(x, f, a)
           \/ Rejoin /\ \E h \in MemV(x, a, {}) \cap Acts :
                 /\ InCycle(a, h) /\ ~\E b \in BoxesAt(x, e) : b.h = h
                 /\ SealK(x, a, h) # 0
                 /\ IF LeaveOut = "commit" THEN RotOK(x, a, SealK(x, a, h))
                                           ELSE ~BackBox(x, a, SealK(x, a, h))

Remove(dp) ==
  /\ dp \notin done /\ Len(ep) < MaxE
  /\ IsAdm(dp[3], dp[2])
  /\ Rotate(dp[3], dp[2], {dp}, TRUE)
  /\ done' = done \cup {dp}
  /\ UNCHANGED <<rs, krs, wr, evd, nw>>

EagerRot(p) ==
  /\ p \notin evd /\ Len(ep) < MaxE /\ IsAdm(p[1], p[2])
  /\ Rotate(p[1], p[2], {}, FALSE)
  /\ evd' = evd \cup {p}
  /\ UNCHANGED <<rs, krs, wr, done, nw>>

ForcedRot(x, a) ==
  /\ Len(ep) < MaxE /\ NeedRot(x, a)
  /\ Rotate(x, a, {}, ~Covers(x, NewestV(x, a), a))
  /\ UNCHANGED <<rs, krs, wr, done, evd, nw>>

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
  /\ UNCHANGED <<rs, kn, krs, wr, done, nw>>

Learn(x, e) ==
  /\ e \in Ids /\ e \notin kn[x]
  /\ kn' = [kn EXCEPT ![x] = @ \cup {e} \cup (IF Carry THEN Named(ep[e].bx) ELSE {})]
  /\ UNCHANGED <<ep, rs, krs, wr, done, evd, nw>>

LearnRs(x, r) ==
  /\ r \in rs /\ r \notin krs[x]
  /\ krs' = [krs EXCEPT ![x] = @ \cup {r}]
  /\ kn' = [kn EXCEPT ![x] = @ \cup (IF Carry THEN Named({r}) ELSE {})]
  /\ UNCHANGED <<ep, rs, wr, done, evd, nw>>

Reseal(x, a, h) ==
  /\ IsAdm(x, a) /\ h \in MemV(x, a, {}) \cap Acts
  /\ \E e \in Cur(x, a) \cap Sec(x) :
       /\ Covers(x, e, a)
       /\ ~\E b \in BoxesAt(x, e) : b.h = h
       /\ LET k == SealK(x, a, h)
              r == [e |-> e, h |-> h, key |-> KK(k)]
          IN /\ k # 0
             /\ InCycle(a, h) => CC(x, a, k, Cur(x, a), KOf(x, a) \ Cur(x, a))
             /\ rs' = rs \cup {r}
             /\ krs' = [krs EXCEPT ![x] = @ \cup {r}]
  /\ UNCHANGED <<ep, kn, wr, done, evd, nw>>

\* the inside-member premise: x knows d left M (a holder of a) and holds a
\* keyset of M made knowing it that lists every honest keyset of M made
\* without knowing it
P2Prem(x, a, dp) ==
  /\ dp[2] \in ActHolders(a) /\ dp \in Known(x)
  /\ \A k \in Ids : (ep[k].act = dp[2] /\ ~ep[k].forged /\ dp \notin ep[k].knows) =>
        \E j \in kn[x] : ep[j].act = dp[2] /\ ~ep[j].forged /\ dp \in ep[j].knows /\ k \in AncH(j)

Write(x, a) ==
  /\ a \in WriteTo /\ IsAdm(x, a) /\ nw < Writes
  /\ LET e == NewestV(x, a)
     IN /\ e \in Sec(x) /\ Covers(x, e, a) /\ ~StaleAt(x, e)
        /\ wr' = wr \cup {[a |-> a, e |-> e, w |-> x,
                           p1 |-> {dp \in Known(x) : dp[2] = a},
                           p2 |-> {dp \in Deps : P2Prem(x, a, dp)},
                           p3 |-> IF {r \in rs : r.e = e} \subseteq krs[x]
                                  THEN {dp \in Deps : \A y \in Learners :
                                          IsAdm(y, a) => P2Prem(y, a, dp)}
                                  ELSE {}]}
  /\ nw' = nw + 1
  /\ UNCHANGED <<ep, rs, kn, krs, done, evd>>

Next ==
  \/ \E dp \in Deps : Remove(dp)
  \/ \E p \in Eager : EagerRot(p)
  \/ \E d \in Forgers : Forge(d)
  \/ \E x \in Learners, a \in Acts : ForcedRot(x, a) \/ Write(x, a)
  \/ \E x \in Learners, a \in Acts, h \in Acts : Reseal(x, a, h)
  \/ \E x \in Learners : (\E e \in Ids : Learn(x, e)) \/ (\E r \in rs : LearnRs(x, r))

Fairness ==
  /\ \A x \in Learners : WF_vars((\E e \in Ids : Learn(x, e)) \/ (\E r \in rs : LearnRs(x, r)))
  /\ \A x \in Learners, a \in Acts : WF_vars(ForcedRot(x, a))
  /\ \A x \in Learners, a \in Acts : WF_vars(\E h \in Acts : Reseal(x, a, h))

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---- properties
CurMem(a) == Holders(a) \ {dp[1] : dp \in {q \in done : q[2] = a}}
CurDevs(a) == UNION {CurMem(b) \ Acts : b \in {a} \cup HClos(a)}
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

\* eventually every writer's next epoch is closed to every removed device
\* that no longer reaches the actor (any depth, cycles included)
Excludes == <>[](\A dp \in done : \A a \in Acts : \A x \in Learners :
                   (dp[1] \notin CurDevs(a) /\ IsAdm(x, a)) => NewestV(x, a) \notin ReachD(dp[1]))
\* no lockout: every current device of an actor eventually holds every
\* current epoch of it and every epoch content was written under
CurrentOpens == <>[](\A a \in Acts : \A v \in CurDevs(a) \cap Learners : GCur(a) \subseteq Sec(v))
ReadsAll == <>[](\A c \in wr : \A v \in CurDevs(c.a) \cap Learners : c.e \in Sec(v))
\* rotations stop within MaxE (no ping-pong)
Settles == <>[](\A x \in Learners, a \in Acts : ~NeedRot(x, a))
=============================================================================

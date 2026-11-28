---- MODULE ForkRot ----
\* Rotations under a permanent fork (spec/crypto.md \S 4; notes/disputes.md).
\* Thing A, holder actor M of A,
\* read role. Two sides p, q: at the start each side's admin removed the
\* other's, each node trusts its own removal for good (forks are permanent),
\* and each side rotates A and M by its own rules. ForkM: each side holds the
\* other's keysets of M invalid (the fight is on M) and knows a departure from
\* M its own keysets cover; ForkA: alike for A's epochs and re-seals. ForkM
\* without ForkA is a thing whose writers' rights do not flow through the
\* forked holder actor (the fight on M, or on a holder actor A of a thing above
\* it, the admins of A writing it directly): A's epochs are valid on both sides
\* and box M at keysets valid on one. One node per side, holding M's secrets
\* (judging M's keysets by names); content writes always pending, so a
\* rotation due before the next write is made; any delivery order, an epoch of A
\* arriving with the keysets it names (Carried); unprompted rotations of M up
\* to MaxM per side.
\* Rule: "now" (spec/crypto.md \S 4 as written: a box naming a keyset held
\* invalid is stale, its epoch blocked, a rotation due for it; every valid
\* rotation supersedes what it lists); "exclude" (an epoch whose rotation
\* commit boxes a holder actor at a keyset held invalid is not established
\* there); "foreign" (such an epoch is foreign there: it supersedes nothing
\* there and makes no rotation due there; a box naming a keyset held invalid
\* still blocks it); "supsonly" (a foreign epoch supersedes nothing, but makes
\* a rotation due) and "dueonly" (it makes none due, but supersedes).
\* Records: rotations leaving M out record it with causes (Left out), and M is
\* re-keyed for a counting record at a current keyset.
EXTENDS Naturals, FiniteSets

CONSTANTS Rule, ForkA, ForkM, Records, MaxM, QA, QM

Sides == {"p", "q"}
Other(s) == IF s = "p" THEN "q" ELSE "p"
Rm(s) == IF s = "p" THEN "rp" ELSE "rq"   \* s's removal of the other side's party

VARIABLES mk,  \* M's keysets: index -> [by, lists, ht, knows]
          ak,  \* A's epochs: index -> [by, lists, box (keysets of M; {}: left out), rec ([k, cz]), knows]
          rs,  \* re-seals: [e, ks, by]
          hm, ha, hr, hc,  \* per side: keysets, epochs, re-seals, removals held
          na, nm, um       \* per side: rotations of A, of M, unprompted ones of M

vars == <<mk, ak, rs, hm, ha, hr, hc, na, nm, um>>

Len(f) == Cardinality(DOMAIN f)
Ext(f, x) == [i \in 1..Len(f) + 1 |-> IF i <= Len(f) THEN f[i] ELSE x]

\* validity: the other side's writes on a forked thing are invalid
VM(s, k) == ~ForkM \/ mk[k].by \in {"0", s}
VA(s, e) == ~ForkA \/ ak[e].by \in {"0", s}
InvM(s, k) == k \in hm[s] /\ ~VM(s, k)
HVM(s) == {k \in hm[s] : VM(s, k)}

RECURSIVE Anc(_, _)
Anc(s, k) == LET l == mk[k].lists \cap HVM(s) IN l \cup UNION {Anc(s, j) : j \in l}
CurM(s) == {k \in HVM(s) : ~\E j \in HVM(s) : k \in mk[j].lists}
\* M's keyset covers the departure from M s knows (its rotator knew it)
CovM(s, k) == ~ForkM \/ s \in mk[k].knows
CovA(s, e) == ~ForkA \/ s \in ak[e].knows

\* an epoch boxing M (by its own rotation) at a keyset held invalid
Rests(s, e) == \E k \in ak[e].box : InvM(s, k)
EA(s) == {e \in ha[s] : VA(s, e) /\ ~(Rule = "exclude" /\ Rests(s, e))}
Foreign(s, e) == Rule \in {"foreign", "supsonly", "dueonly"} /\ Rests(s, e)
CurA(s) == {e \in EA(s) : ~\E j \in EA(s) : ~(Foreign(s, j) /\ Rule # "dueonly") /\ e \in ak[j].lists}

\* left-out records of A's current epochs, causes joined per keyset
Raw(s) == UNION {ak[e].rec : e \in CurA(s)}
Merge(R) == {[k |-> k, cz |-> UNION {q.cz : q \in {p \in R : p.k = k}}] : k \in {q.k : q \in R}}
Recs(s) == Merge(Raw(s))
\* a removal (edge cause) stands where it is valid: on its own side
Stands(s, c) == c = Rm(s)
Counts(s, q) == \E c \in q.cz : c \notin hc[s] \/ Stands(s, c)
RecBlocks(s, k) == Records /\ \E q \in Recs(s) : q.k = k /\ Counts(s, q)

Superseded(s, k) == \E j \in HVM(s) : k \in mk[j].lists
StaleK(s, k) == InvM(s, k) \/ Superseded(s, k)
BlockedS(s, S) == (\E k \in S : StaleK(s, k) \/ RecBlocks(s, k)) \/ \A k \in S : ~CovM(s, k)

Boxes(s, e) == {S \in {ak[e].box} \cup {r.ks : r \in {x \in hr[s] : x.e = e /\ (~ForkA \/ x.by = s)}} : S # {}}
Blocked(s, e) == ~CovA(s, e) \/ \E S \in Boxes(s, e) : BlockedS(s, S)
\* the knowing re-key: an uncovered departure or a stale box; "foreign": none
\* for a foreign epoch (it is blocked, and supersedes nothing)
KnowDue(s, e) == ~(Foreign(s, e) /\ Rule # "supsonly") /\ (~CovA(s, e) \/ \E S \in Boxes(s, e) : \E k \in S : StaleK(s, k))

Anchors(s) == UNION {S \cap HVM(s) : S \in UNION {Boxes(s, e) : e \in CurA(s)}}
Newest(S) == CHOOSE k \in S : \A j \in S : mk[j].ht < mk[k].ht \/ (mk[j].ht = mk[k].ht /\ j <= k)
From(s, a) == {k \in HVM(s) : k = a \/ a \in Anc(s, k)}
SealSet(s) ==
  LET as == Anchors(s)
      all == {k \in HVM(s) : \A a \in as : k = a \/ a \in Anc(s, k)}
      tops == {a \in as : ~\E b \in as : a \in Anc(s, b)}
  IN IF all # {} THEN {Newest(all)}
     ELSE IF \E a \in tops : From(s, a) = {} THEN {}
     ELSE {Newest(From(s, a)) : a \in tops}
SealOK(s) == SealSet(s) # {} /\ ~BlockedS(s, SealSet(s))

RotMDue(s) == \E k \in CurM(s) : ~CovM(s, k) \/ RecBlocks(s, k)
RotADue(s) == \/ \A e \in CurA(s) : Blocked(s, e)
              \/ \E e \in CurA(s) : KnowDue(s, e)
RotA(s) ==
  LET out == ~SealOK(s)
      new == {[k |-> k, cz |-> {Rm(s)}] : k \in {j \in CurM(s) : ~CovM(s, j)}}
  IN /\ RotADue(s)
     \* M's due rotation comes first (rotations due are made bottom-up), but
     \* for the side's first rotation of A: a removal's rotation, or one made
     \* before the pass ends, leaving M out
     /\ ~RotMDue(s) \/ na[s] = 0
     /\ ak' = Ext(ak, [by |-> s, lists |-> CurA(s),
                       box |-> IF out THEN {} ELSE SealSet(s),
                       rec |-> IF out /\ Records THEN Merge(Recs(s) \cup new) ELSE {},
                       knows |-> {s}])
     /\ ha' = [ha EXCEPT ![s] = @ \cup {Len(ak) + 1}]
     /\ na' = [na EXCEPT ![s] = @ + 1]
     /\ UNCHANGED <<mk, rs, hm, hr, hc, nm, um>>

ResealAt(s) == {e \in CurA(s) : Boxes(s, e) = {}}
Reseal(s) ==
  /\ ResealAt(s) # {} /\ SealOK(s)
  /\ \E e \in ResealAt(s) :
       LET r == [e |-> e, ks |-> SealSet(s), by |-> s] IN
       /\ r \notin rs
       /\ rs' = rs \cup {r}
       /\ hr' = [hr EXCEPT ![s] = @ \cup {r}]
  /\ UNCHANGED <<mk, ak, hm, ha, hc, na, nm, um>>

NewK(s) == [by |-> s, lists |-> CurM(s), knows |-> {s},
            ht |-> 1 + LET hs == {mk[j].ht : j \in CurM(s)} IN CHOOSE h \in hs : \A g \in hs : g <= h]
RotM(s) ==
  /\ RotMDue(s) \/ um[s] < MaxM
  /\ um' = [um EXCEPT ![s] = IF RotMDue(s) THEN @ ELSE @ + 1]
  /\ mk' = Ext(mk, NewK(s))
  /\ hm' = [hm EXCEPT ![s] = @ \cup {Len(mk) + 1}]
  /\ nm' = [nm EXCEPT ![s] = @ + 1]
  /\ UNCHANGED <<ak, rs, ha, hr, hc, na>>

DeliverM(s) == \E k \in (1..Len(mk)) \ hm[s] :
  /\ hm' = [hm EXCEPT ![s] = @ \cup {k}]
  /\ UNCHANGED <<mk, ak, rs, ha, hr, hc, na, nm, um>>
DeliverA(s) == \E e \in (1..Len(ak)) \ ha[s] :
  /\ ha' = [ha EXCEPT ![s] = @ \cup {e}]
  /\ hm' = [hm EXCEPT ![s] = @ \cup ak[e].box \cup {q.k : q \in ak[e].rec}]
  /\ UNCHANGED <<mk, ak, rs, hr, hc, na, nm, um>>
DeliverR(s) == \E r \in rs \ hr[s] :
  /\ hr' = [hr EXCEPT ![s] = @ \cup {r}]
  /\ hm' = [hm EXCEPT ![s] = @ \cup r.ks]
  /\ UNCHANGED <<mk, ak, rs, ha, hc, na, nm, um>>
DeliverC(s) ==
  /\ Rm(Other(s)) \notin hc[s]
  /\ hc' = [hc EXCEPT ![s] = @ \cup {Rm(Other(s))}]
  /\ UNCHANGED <<mk, ak, rs, hm, ha, hr, na, nm, um>>

Init ==
  /\ mk = [i \in {1} |-> [by |-> "0", lists |-> {}, ht |-> 0, knows |-> {}]]
  /\ ak = [i \in {1} |-> [by |-> "0", lists |-> {}, box |-> {1}, rec |-> {}, knows |-> {}]]
  /\ rs = {}
  /\ hm = [s \in Sides |-> {1}]
  /\ ha = [s \in Sides |-> {1}]
  /\ hr = [s \in Sides |-> {}]
  /\ hc = [s \in Sides |-> {Rm(s)}]
  /\ na = [s \in Sides |-> 0]
  /\ nm = [s \in Sides |-> 0]
  /\ um = [s \in Sides |-> 0]

Next == \E s \in Sides :
          \/ RotA(s) \/ Reseal(s) \/ RotM(s)
          \/ DeliverM(s) \/ DeliverA(s) \/ DeliverR(s) \/ DeliverC(s)

Spec == Init /\ [][Next]_vars

\* Quiet: rotations stop. Each side's rotations stay within a bound set by the
\* fork's own events (QA of A, QM of M; at MaxM 0: 3 and 1: each shared epoch,
\* one leaving M out and so foreign nowhere, that the other side re-seals M
\* into costs a side one rotation); a rule under which each side's rotation
\* makes the other's due passes any bound
Quiet == \A s \in Sides : na[s] <= QA /\ nm[s] <= QM

AllHeld == \A s \in Sides : hm[s] = 1..Len(mk) /\ ha[s] = 1..Len(ak) /\ hr[s] = rs /\ hc[s] = {"rp", "rq"}
Due == \E s \in Sides : RotADue(s) \/ RotMDue(s) \/ (ResealAt(s) # {} /\ SealOK(s)) \/ um[s] < MaxM
\* Live: once all is held and nothing is due, each side writes, under an
\* epoch boxing M at a keyset of its own side (M's readers there read it)
Live == (AllHeld /\ ~Due) =>
          \A s \in Sides : \E e \in CurA(s) : ~Blocked(s, e) /\ \E S \in Boxes(s, e) : S \subseteq HVM(s)
\* Kept: once settled, every epoch valid at a side (its rotator wrote under it)
\* is that side's current epoch or listed by one, through history (its later
\* holders read it)
RECURSIVE Hist(_)
Hist(S) == LET T == S \cup UNION {ak[e].lists : e \in S} IN IF T = S THEN S ELSE Hist(T)
Kept == (AllHeld /\ ~Due) =>
          \A e \in 1..Len(ak), s \in Sides : VA(s, e) => e \in Hist(CurA(s))
====

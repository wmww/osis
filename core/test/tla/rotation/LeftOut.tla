---- MODULE LeftOut ----
\* A holder actor M left out of thing A, and what keeps it out (spec/crypto.md
\* \S 4 Left out; notes/holder-actors.md, Left out). One cause c (a departure from
\* M or below it, or a keyset of a holder below M making a box stale: what made a
\* keyset of M bad) removes party x; c is invalid wherever its invalidator i is
\* held too (a concurrent demotion of c's author, a side switch). x opens every
\* keyset of M made without knowing c valid. Sealers w (reads M: judges a keyset
\* of M by its names) and c (holds none of M's secrets: judges by order) rotate
\* and re-seal A; r rotates M, holding none of M's secrets unless RSec. An
\* ignorant rotation of M made after c (Ignorant) is the adversary's one-shot
\* step. Seal anchors at the keysets A's current boxes name, jointly where they
\* fork. Any delivery order; a rotation of A delivers the keysets it names and
\* what it carries.
\* Rule: "old" (a record counts whatever its cause; Seal takes only a keyset past
\* it; M's rotator rotates where no recorded keyset is current and nothing is
\* past it: Left out for good), "cause" (a record names its cause and carries it;
\* it counts only while its cause stands: blocks its keyset; any rotator of M
\* holding a counting record of a current keyset rotates M), "nocarry" (as
\* cause, the cause not carried), "nofact" (no record; the cause carried),
\* "nodue" (as cause, no rotation of M for a counting record).
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Rule, HasInv, Ignorant, RSec, MaxA, MaxM

Sealers == {"w", "c"}
Nodes == Sealers \cup {"r"}
Secret == IF RSec THEN {"w", "r"} ELSE {"w"}
CPos == 1     \* c's place in the order of making (M's initial keyset: 0)
Events == IF HasInv THEN {"c", "i"} ELSE {"c"}

VARIABLES mk,   \* M's keysets: [lists, knows (maker held c valid), pos, ht]
          ak,   \* A's epochs: [lists, box (keysets of M: joint when two; {}:
                \* left out), rec, cz, pos; lo: the keysets its maker left M
                \* out at, a ghost]
          rs,   \* re-seals: [e, ks]
          hm, ha, hr, hc,  \* per node: keysets, epochs, re-seals, causes held
          wr,   \* <<epoch, writer>>: content written knowing c
          t,    \* order of making
          ign   \* the ignorant rotation made

vars == <<mk, ak, rs, hm, ha, hr, hc, wr, t, ign>>

CV(n) == "c" \in hc[n] /\ "i" \notin hc[n]

RECURSIVE Anc(_, _)
Anc(n, k) == LET l == mk[k].lists \cap hm[n] IN l \cup UNION {Anc(n, q) : q \in l}

CurM(n) == {k \in hm[n] : ~\E j \in hm[n] : k \in mk[j].lists}
StaleK(n, k) == \E j \in hm[n] : k \in mk[j].lists
\* k covers c at n: by names where n holds M's secrets, else by order
Covered(n, k) == ~CV(n) \/ IF n \in Secret THEN mk[k].knows ELSE mk[k].pos > CPos

CurA(n) == {e \in ha[n] : ~\E j \in ha[n] : e \in ak[j].lists}
Recs(n) == UNION {ak[e].rec : e \in CurA(n)}
Counts(n) == IF Rule = "old" THEN TRUE ELSE CV(n)
RecBlocks(n, k) == Rule # "old" /\ \E q \in Recs(n) : q.k = k /\ Counts(n)
BlockedK(n, k) == ~Covered(n, k) \/ StaleK(n, k) \/ RecBlocks(n, k)
\* a joint box as a whole: by a box when any keyset is, by c when every one is
BlockedS(n, S) == (\E k \in S : StaleK(n, k) \/ RecBlocks(n, k)) \/ \A k \in S : ~Covered(n, k)

\* the box sets of e n holds (each keyset held)
Boxes(n, e) == {S \in {ak[e].box} \cup {s.ks : s \in {s2 \in hr[n] : s2.e = e}} : S # {} /\ S \subseteq hm[n]}
Anchors(n) == UNION UNION {Boxes(n, e) : e \in CurA(n)}
\* "old": past each record: descends from it, or (nothing held descends from
\* it) made after the record
Past(n, k) == \A q \in Recs(n) :
                q.k \in Anc(n, k) \/ ((~\E j \in hm[n] : q.k \in Anc(n, j)) /\ mk[k].pos > q.at)
Cands(n) == {k \in hm[n] : Rule = "old" => Past(n, k)}
Newest(S) == CHOOSE k \in S : \A j \in S : mk[j].ht < mk[k].ht \/ (mk[j].ht = mk[k].ht /\ j <= k)
From(n, a) == {k \in Cands(n) : k = a \/ a \in Anc(n, k)}
\* Seal: the newest candidate from every anchor, else jointly the newest from
\* each (with none from some anchor: {}, left out)
SealSet(n) ==
  LET as == Anchors(n)
      all == {k \in Cands(n) : \A a \in as : k = a \/ a \in Anc(n, k)}
      tops == {a \in as : ~\E b \in as : a \in Anc(n, b)}
  IN IF all # {} THEN {Newest(all)}
     ELSE IF as = {} \/ \E a \in tops : From(n, a) = {} THEN {}
     ELSE {Newest(From(n, a)) : a \in tops}
SealOK(n) == SealSet(n) # {} /\ ~BlockedS(n, SealSet(n))

EncBlocked(n, e) == \E S \in Boxes(n, e) : BlockedS(n, S)

RotADue(n) == \E e \in CurA(n) : EncBlocked(n, e)
RotAOK(n) == RotADue(n) /\ Len(ak) <= MaxA
RotA(n) ==
  LET out == ~SealOK(n)
      new == {k \in SealSet(n) : BlockedK(n, k) /\ ~\E q \in Recs(n) : q.k = k}
  IN /\ RotAOK(n)
     /\ ak' = Append(ak, [lists |-> CurA(n),
                          box |-> IF out THEN {} ELSE SealSet(n),
                          rec |-> IF ~out \/ Rule = "nofact" THEN {} ELSE
                                    Recs(n) \cup {[k |-> k, at |-> t + 1] : k \in new},
                          lo |-> IF out THEN SealSet(n) ELSE {},
                          cz |-> IF out /\ Rule \in {"cause", "nofact", "nodue"} THEN hc[n] ELSE {},
                          pos |-> t + 1])
     /\ ha' = [ha EXCEPT ![n] = @ \cup {Len(ak) + 1}]
     /\ t' = t + 1
     /\ UNCHANGED <<mk, rs, hm, hr, hc, wr, ign>>

ResealAt(n) == {e \in CurA(n) : Boxes(n, e) = {}}
ResealOK(n) == ResealAt(n) # {} /\ SealOK(n)
Reseal(n) ==
  /\ ResealOK(n)
  /\ \E e \in ResealAt(n) :
       /\ rs' = rs \cup {[e |-> e, ks |-> SealSet(n)]}
       /\ hr' = [hr EXCEPT ![n] = @ \cup {[e |-> e, ks |-> SealSet(n)]}]
  /\ UNCHANGED <<mk, ak, hm, ha, hc, wr, t, ign>>

\* M's rotator: the knowing re-key, and the rule's own clause
LeftOutForGood == /\ \E q \in Recs("r") : q.k \in hm["r"]
                  /\ \A q \in Recs("r") : q.k \notin CurM("r")
                  /\ SealSet("r") = {}
RotMDue == \/ \E k \in CurM("r") : ~Covered("r", k)
           \/ Rule = "old" /\ LeftOutForGood
           \/ Rule \in {"cause", "nocarry"} /\ \E q \in Recs("r") : q.k \in CurM("r") /\ Counts("r")
RotMOK == RotMDue /\ Len(mk) <= MaxM + (IF ign THEN 1 ELSE 0)
NewK(ls, kn) == [lists |-> ls, knows |-> kn, pos |-> t + 1,
                 ht |-> 1 + LET hs == {mk[q].ht : q \in ls} IN CHOOSE h \in hs : \A g \in hs : g <= h]
RotM ==
  /\ RotMOK
  /\ mk' = Append(mk, NewK(CurM("r"), CV("r")))
  /\ hm' = [hm EXCEPT !["r"] = @ \cup {Len(mk) + 1}]
  /\ t' = t + 1
  /\ UNCHANGED <<ak, rs, ha, hr, hc, wr, ign>>

\* a rotation of M by an admin that has not received c (made after it)
Ign ==
  /\ Ignorant /\ ~ign
  /\ mk' = Append(mk, NewK({1}, FALSE))
  /\ ign' = TRUE
  /\ t' = t + 1
  /\ UNCHANGED <<ak, rs, hm, ha, hr, hc, wr>>

\* (w's content stands for any: c's would add states, not cases)
Write(n) ==
  /\ n = "w" /\ CV(n)
  /\ \E e \in CurA(n) : ~EncBlocked(n, e) /\ <<e, n>> \notin wr /\ wr' = wr \cup {<<e, n>>}
  /\ UNCHANGED <<mk, ak, rs, hm, ha, hr, hc, t, ign>>

DeliverC(n) == \E x \in Events \ hc[n] :
  /\ hc' = [hc EXCEPT ![n] = @ \cup {x}]
  /\ UNCHANGED <<mk, ak, rs, hm, ha, hr, wr, t, ign>>
DeliverM(n) == \E k \in (1..Len(mk)) \ hm[n] :
  /\ hm' = [hm EXCEPT ![n] = @ \cup {k}]
  /\ UNCHANGED <<mk, ak, rs, ha, hr, hc, wr, t, ign>>
\* an epoch of A arrives with the keysets its box and records name (Carried),
\* and, by rule, the causes it carries
DeliverA(n) == \E e \in (1..Len(ak)) \ ha[n] :
  /\ ha' = [ha EXCEPT ![n] = @ \cup {e}]
  /\ hm' = [hm EXCEPT ![n] = @ \cup ak[e].box \cup {q.k : q \in ak[e].rec}]
  /\ hc' = [hc EXCEPT ![n] = @ \cup ak[e].cz]
  /\ UNCHANGED <<mk, ak, rs, hr, wr, t, ign>>
DeliverR(n) == \E s \in rs \ hr[n] :
  /\ hr' = [hr EXCEPT ![n] = @ \cup {s}]
  /\ hm' = [hm EXCEPT ![n] = @ \cup s.ks]
  /\ UNCHANGED <<mk, ak, rs, ha, hc, wr, t, ign>>

Init ==
  /\ mk = <<[lists |-> {}, knows |-> FALSE, pos |-> 0, ht |-> 0]>>
  /\ ak = <<[lists |-> {}, box |-> {1}, rec |-> {}, lo |-> {}, cz |-> {}, pos |-> 0]>>
  /\ rs = {}
  /\ hm = [n \in Nodes |-> {1}]
  /\ ha = [n \in Nodes |-> {1}]
  /\ hr = [n \in Nodes |-> {}]
  /\ hc = [n \in Nodes |-> {}]
  /\ wr = {}
  /\ t = CPos
  /\ ign = FALSE

Next == \/ \E n \in Sealers : RotA(n) \/ Reseal(n) \/ Write(n)
        \/ RotM \/ Ign
        \/ \E n \in Nodes : DeliverC(n) \/ DeliverM(n) \/ DeliverA(n) \/ DeliverR(n)

Spec == Init /\ [][Next]_vars

\* x opens an epoch of A boxing M at keysets each made without knowing c, or one
\* a later epoch it opens lists (history)
RECURSIVE Opens(_)
Opens(S) == LET T == S \cup UNION {ak[e].lists : e \in S} IN IF T = S THEN S ELSE Opens(T)
BoxedAll(e) == {S \in {ak[e].box} \cup {s.ks : s \in {s2 \in rs : s2.e = e}} : S # {}}
XOpensVia(P(_)) == Opens({e \in 1..Len(ak) : \E S \in BoxedAll(e) : \A k \in S : ~mk[k].knows /\ P(k)})

\* NoLeak (spec/crypto.md \S 4: the departed party opens A's epochs so sealed
\* only through a keyset of M made after c without knowing it): content written
\* knowing c is opened by x through no box at keysets made before c, while c
\* is valid
NoLeak == ~HasInv => \A w \in wr : w[1] \notin XOpensVia(LAMBDA k : mk[k].pos < CPos)

\* Live: once everything is held and no step is left, M is boxed at A's current
\* epochs and every sealer may write
AllHeld == /\ \A n \in Nodes : hc[n] = Events /\ hm[n] = 1..Len(mk) /\ ha[n] = 1..Len(ak) /\ hr[n] = rs
           /\ Ignorant => ign
\* (bounds aside: a state the bounds stop is no settled one)
Due == \E n \in Sealers : RotADue(n) \/ ResealOK(n) \/ RotMDue
Good == \A n \in Sealers : \A e \in CurA(n) : Boxes(n, e) # {} /\ ~EncBlocked(n, e)
Live == (AllHeld /\ ~Due) => Good

\* NoUndo: while c is valid, no re-seal boxes M at a keyset an epoch's maker
\* left it out at (its maker would rotate A again: one rotation of A per
\* re-seal, for good where no rotator of M re-keys)
NoUndo == ~HasInv => \A s \in rs : s.ks \cap ak[s.e].lo = {}
====

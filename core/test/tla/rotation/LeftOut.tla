---- MODULE LeftOut ----
\* A holder actor M left out of thing A, and what keeps it out (spec/crypto.md
\* \S 4 Left out; notes/holder-actors.md, Left out). One cause c (any block
\* clause: every one names a commit) removes party x; c is void wherever its
\* invalidator i is held (a concurrent demotion of its author, a side switch).
\* Kind "edge": c writes edges (a departure, a keyless grant) and stands while
\* valid; "rot": c writes a keyset (a stale box's superseder, the epoch a box or
\* rotator departure holds, a keyset held invalid) and stands while held. x opens
\* every keyset of M made without knowing c valid. Sealers w (reads M: judges a
\* keyset of M by its names) and c (holds none of M's secrets: judges by order)
\* rotate and re-seal A; r rotates M, holding none of M's secrets unless RSec.
\* An ignorant rotation of M made after c (Ignorant) is the adversary's one-shot
\* step. A hostile writer h of A (Hostile) rotates A leaving M out and recording
\* any keyset of M with any causes: c, f (held nowhere), g (held everywhere,
\* standing nowhere), until its removal hr, which every epoch made without
\* knowing it then misses. Seal anchors at the keysets A's current boxes name,
\* jointly where they fork. Any delivery order: a rotation of A arrives with the
\* keysets it names (Carried), causes on their own.
\* Rule: "cause" (the rule: a record names its causes; it counts while one
\* stands or is not held, and blocks its keyset; any rotator of M holding a
\* counting record of a current keyset rotates M; rotations of A copy records),
\* "old" (a record counts whatever its cause; Seal takes only a keyset past it;
\* M's rotator rotates where no recorded keyset is current and nothing is past
\* it: Left out for good), "voidunheld" (as cause, a record whose causes are not
\* held counts nothing), "copyheld" (as cause, a copy keeps only the causes its
\* rotator holds), "wait" (as cause, A's keyset counts as not arrived until its
\* records' causes are held, and its holders rotate past it), "anyrec" (as cause, M
\* rotated for a counting record whatever keyset it names), "noadd" (as cause, a
\* keyset already recorded keeps only the causes recorded), "nofact" (no record),
\* "nodue" (as cause, no rotation of M for a counting record).
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Rule, Kind, HasC, HasInv, Ignorant, RSec, Hostile, MaxA, MaxM, MaxH

Sealers == {"w", "c"}
Nodes == Sealers \cup {"r"}
Secret == IF RSec THEN {"w", "r"} ELSE {"w"}
CPos == 1     \* c's place in the order of making (M's initial keyset: 0)
Start == IF Hostile THEN {"g"} ELSE {}
HCauses == (IF HasC THEN {"c"} ELSE {}) \cup {"f", "g"}

VARIABLES mk,   \* M's keysets: [lists, knows (rotator held c valid), pos, ht]
          ak,   \* A's epochs: [lists, box (keysets of M: joint when two; {}:
                \* left out), rec ([k, cz, at]), pos, by ("h", else "s": a sealer),
                \* khr (rotator held hr);
                \* lo: the keysets its rotator left M out at, a ghost]
          rs,   \* re-seals: [e, ks]
          hm, ha, hr, hc,  \* per node: keysets, epochs, re-seals, events held
          wr,   \* <<epoch, writer>>: content written knowing c
          t,    \* order of making
          ign,  \* the ignorant rotation made
          hrm,  \* h removed (it makes nothing after)
          hn,   \* h's rotations
          quiet, \* sealers that rotated A and received nothing since (ghost; kept
                 \* with Hostile only, where NoChurn is checked)
          churn, \* a sealer rotated A twice with nothing received between (ghost)
          hk    \* the keysets of M h recorded (ghost)

vars == <<mk, ak, rs, hm, ha, hr, hc, wr, t, ign, hrm, hn, quiet, churn, hk>>

Events == (IF HasC THEN {"c"} ELSE {}) \cup (IF HasInv THEN {"i"} ELSE {})
          \cup (IF hrm THEN {"hr"} ELSE {}) \cup Start

CV(n) == "c" \in hc[n] /\ "i" \notin hc[n]

RECURSIVE Anc(_, _)
Anc(n, k) == LET l == mk[k].lists \cap hm[n] IN l \cup UNION {Anc(n, q) : q \in l}

CurM(n) == {k \in hm[n] : ~\E j \in hm[n] : k \in mk[j].lists}
StaleK(n, k) == \E j \in hm[n] : k \in mk[j].lists
\* k covers c at n: by names where n holds M's secrets, else by order
Covered(n, k) == ~CV(n) \/ IF n \in Secret THEN mk[k].knows ELSE mk[k].pos > CPos

CurA(n) == {e \in ha[n] : ~\E j \in ha[n] : e \in ak[j].lists}
\* the records of A's current epochs, one per keyset, causes joined
Raw(n) == UNION {ak[e].rec : e \in CurA(n)}
Merge(R) == {[k |-> k,
               cz |-> UNION {q.cz : q \in {p \in R : p.k = k}},
               at |-> CHOOSE a \in {q.at : q \in {p \in R : p.k = k}} :
                        \A p \in R : p.k = k => a <= p.at]
              : k \in {q.k : q \in R}}
Recs(n) == Merge(Raw(n))
\* a held cause stands: c while valid ("edge") or while held ("rot"); g nowhere
Stands(n, x) == x = "c" /\ (Kind = "rot" \/ "i" \notin hc[n])
Counts(n, q) == CASE Rule = "old" -> TRUE
                  [] Rule = "voidunheld" -> \E x \in q.cz : x \in hc[n] /\ Stands(n, x)
                  [] OTHER -> \E x \in q.cz : x \notin hc[n] \/ Stands(n, x)
RecBlocks(n, k) == Rule # "old" /\ \E q \in Recs(n) : q.k = k /\ Counts(n, q)
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

\* h held the secret of every epoch made without knowing its removal
EncBlocked(n, e) == (\E S \in Boxes(n, e) : BlockedS(n, S)) \/ ("hr" \in hc[n] /\ ~ak[e].khr)
\* "wait": an epoch whose records' causes n lacks has not arrived there
Arrived(n, e) == Rule # "wait" \/ \A q \in ak[e].rec : q.cz \subseteq hc[n]

RotADue(n) == \/ \E e \in CurA(n) : EncBlocked(n, e)
              \/ \E e \in CurA(n) : ak[e].by = "s" /\ ~Arrived(n, e)
RotAOK(n) == RotADue(n) /\ Len(ak) <= MaxA
RotA(n) ==
  LET out == ~SealOK(n)
      new == {k \in SealSet(n) : ~Covered(n, k) /\ (Rule = "noadd" => ~\E q \in Recs(n) : q.k = k)}
      cp == IF Rule = "copyheld" THEN {[q EXCEPT !.cz = q.cz \cap hc[n]] : q \in Recs(n)} ELSE Recs(n)
  IN /\ RotAOK(n)
     /\ ak' = Append(ak, [lists |-> CurA(n),
                          box |-> IF out THEN {} ELSE SealSet(n),
                          rec |-> IF ~out \/ Rule = "nofact" THEN {} ELSE
                                    Merge(cp \cup {[k |-> k, cz |-> {"c"}, at |-> t + 1] : k \in new}),
                          lo |-> IF out THEN SealSet(n) ELSE {},
                          pos |-> t + 1, by |-> "s", khr |-> "hr" \in hc[n]])
     /\ ha' = [ha EXCEPT ![n] = @ \cup {Len(ak) + 1}]
     /\ t' = t + 1
     /\ churn' = (churn \/ n \in quiet)
     /\ quiet' = IF Hostile THEN quiet \cup {n} ELSE quiet
     /\ UNCHANGED <<mk, rs, hm, hr, hc, wr, ign, hrm, hn, hk>>

ResealAt(n) == {e \in CurA(n) : Boxes(n, e) = {}}
ResealOK(n) == ResealAt(n) # {} /\ SealOK(n)
Reseal(n) ==
  /\ ResealOK(n)
  /\ \E e \in ResealAt(n) :
       /\ rs' = rs \cup {[e |-> e, ks |-> SealSet(n)]}
       /\ hr' = [hr EXCEPT ![n] = @ \cup {[e |-> e, ks |-> SealSet(n)]}]
  /\ UNCHANGED <<mk, ak, hm, ha, hc, wr, t, ign, hrm, hn, quiet, churn, hk>>

\* the hostile writer: leaves M out recording keyset k with causes cz; lists
\* every current epoch
HRot ==
  /\ Hostile /\ ~hrm /\ hn < MaxH /\ Len(ak) <= MaxA
  /\ \E k \in 1..Len(mk), cz \in (SUBSET HCauses) \ {{}} :
     /\ hk' = hk \cup {k}
     /\ ak' = Append(ak, [lists |-> {e \in 1..Len(ak) : ~\E j \in 1..Len(ak) : e \in ak[j].lists},
                         box |-> {}, rec |-> {[k |-> k, cz |-> cz, at |-> t + 1]},
                         lo |-> {}, pos |-> t + 1, by |-> "h", khr |-> FALSE])
  /\ hn' = hn + 1
  /\ t' = t + 1
  /\ UNCHANGED <<mk, rs, hm, ha, hr, hc, wr, ign, hrm, quiet, churn>>
RemoveH ==
  /\ Hostile /\ ~hrm
  /\ hrm' = TRUE
  /\ UNCHANGED <<mk, ak, rs, hm, ha, hr, hc, wr, t, ign, hn, quiet, churn, hk>>

\* M's rotator: the knowing re-key, and the rule's own clause
LeftOutForGood == /\ \E q \in Recs("r") : q.k \in hm["r"]
                  /\ \A q \in Recs("r") : q.k \notin CurM("r")
                  /\ SealSet("r") = {}
RotMDue == \/ \E k \in CurM("r") : ~Covered("r", k)
           \/ Rule = "old" /\ LeftOutForGood
           \/ Rule \in {"cause", "voidunheld", "copyheld", "wait", "noadd"}
                /\ \E q \in Recs("r") : q.k \in CurM("r") /\ Counts("r", q)
           \/ Rule = "anyrec" /\ \E q \in Recs("r") : Counts("r", q)
RotMOK == RotMDue /\ Len(mk) <= MaxM + (IF ign THEN 1 ELSE 0)
NewK(ls, kn) == [lists |-> ls, knows |-> kn, pos |-> t + 1,
                 ht |-> 1 + LET hs == {mk[q].ht : q \in ls} IN CHOOSE h \in hs : \A g \in hs : g <= h]
RotM ==
  /\ RotMOK
  /\ mk' = Append(mk, NewK(CurM("r"), CV("r")))
  /\ hm' = [hm EXCEPT !["r"] = @ \cup {Len(mk) + 1}]
  /\ t' = t + 1
  /\ UNCHANGED <<ak, rs, ha, hr, hc, wr, ign, hrm, hn, quiet, churn, hk>>

\* a rotation of M by an admin that has not received c (made after it)
Ign ==
  /\ Ignorant /\ ~ign
  /\ mk' = Append(mk, NewK({1}, FALSE))
  /\ ign' = TRUE
  /\ t' = t + 1
  /\ UNCHANGED <<ak, rs, hm, ha, hr, hc, wr, hrm, hn, quiet, churn, hk>>

\* (w's content stands for any: c's would add states, not cases)
Write(n) ==
  /\ n = "w" /\ CV(n)
  /\ \E e \in CurA(n) : ~EncBlocked(n, e) /\ <<e, n>> \notin wr /\ wr' = wr \cup {<<e, n>>}
  /\ UNCHANGED <<mk, ak, rs, hm, ha, hr, hc, t, ign, hrm, hn, quiet, churn, hk>>

Got(n) == quiet' = quiet \ {n}
DeliverC(n) == \E x \in Events \ hc[n] :
  /\ hc' = [hc EXCEPT ![n] = @ \cup {x}]
  /\ Got(n)
  /\ UNCHANGED <<mk, ak, rs, hm, ha, hr, wr, t, ign, hrm, hn, churn, hk>>
DeliverM(n) == \E k \in (1..Len(mk)) \ hm[n] :
  /\ hm' = [hm EXCEPT ![n] = @ \cup {k}]
  /\ Got(n)
  /\ UNCHANGED <<mk, ak, rs, ha, hr, hc, wr, t, ign, hrm, hn, churn, hk>>
\* an epoch of A arrives with the keysets its box and records name (Carried)
DeliverA(n) == \E e \in (1..Len(ak)) \ ha[n] :
  /\ ha' = [ha EXCEPT ![n] = @ \cup {e}]
  /\ hm' = [hm EXCEPT ![n] = @ \cup ak[e].box \cup {q.k : q \in ak[e].rec}]
  /\ Got(n)
  /\ UNCHANGED <<mk, ak, rs, hr, hc, wr, t, ign, hrm, hn, churn, hk>>
DeliverR(n) == \E s \in rs \ hr[n] :
  /\ hr' = [hr EXCEPT ![n] = @ \cup {s}]
  /\ hm' = [hm EXCEPT ![n] = @ \cup s.ks]
  /\ Got(n)
  /\ UNCHANGED <<mk, ak, rs, ha, hc, wr, t, ign, hrm, hn, churn, hk>>

Init ==
  /\ mk = <<[lists |-> {}, knows |-> FALSE, pos |-> 0, ht |-> 0]>>
  /\ ak = <<[lists |-> {}, box |-> {1}, rec |-> {}, lo |-> {}, pos |-> 0, by |-> "s", khr |-> FALSE]>>
  /\ rs = {}
  /\ hm = [n \in Nodes |-> {1}]
  /\ ha = [n \in Nodes |-> {1}]
  /\ hr = [n \in Nodes |-> {}]
  /\ hc = [n \in Nodes |-> Start]
  /\ wr = {}
  /\ t = CPos
  /\ ign = FALSE
  /\ hrm = FALSE
  /\ hn = 0
  /\ quiet = {}
  /\ churn = FALSE
  /\ hk = {}

Next == \/ \E n \in Sealers : RotA(n) \/ Reseal(n) \/ Write(n)
        \/ RotM \/ Ign \/ HRot \/ RemoveH
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
\* is valid; content under an epoch h holds (made without knowing its removal)
\* aside, which h may hand x anyway
NoLeak == ~HasInv => \A w \in wr : (Hostile => ak[w[1]].khr) => w[1] \notin XOpensVia(LAMBDA k : mk[k].pos < CPos)

\* Live: once everything is held and no step is left, M is boxed at A's current
\* epochs and every sealer may write
AllHeld == /\ \A n \in Nodes : hc[n] = Events /\ hm[n] = 1..Len(mk) /\ ha[n] = 1..Len(ak) /\ hr[n] = rs
           /\ Ignorant => ign
\* (bounds aside: a state the bounds stop is no settled one)
Due == \E n \in Sealers : RotADue(n) \/ ResealOK(n) \/ RotMDue
Good == \A n \in Sealers : \A e \in CurA(n) : Boxes(n, e) # {} /\ ~EncBlocked(n, e)
Live == (AllHeld /\ ~Due) => Good

\* NoUndo: while c is valid, no re-seal boxes M at a keyset an epoch's rotator
\* left it out at (its rotator would rotate A again: one rotation of A per
\* re-seal, for good where no rotator of M re-keys)
NoUndo == ~HasInv => \A s \in rs : s.ks \cap ak[s.e].lo = {}

\* NoChurn: a sealer rotates A only on news: its own rotation leaves nothing
\* due at it (checked with Hostile)
NoChurn == Hostile => ~churn

\* HostileEnds: with no cause but h's records, M rotates at most once per
\* keyset h recorded, and once h is removed and M's rotator is past them (no
\* current keyset of M at r is one h recorded) no rotation of M is due: a
\* hostile writer's records stop costing once it is removed and M re-keyed
HostileEnds == (Hostile /\ ~HasC) =>
                 /\ Len(mk) - 1 <= Cardinality(hk)
                 /\ (hrm /\ CurM("r") \cap hk = {}) => ~RotMDue
====

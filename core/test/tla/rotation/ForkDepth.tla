---- MODULE ForkDepth ----
\* Foreign keysets at depth (spec/crypto.md \S 4 Holder actors, Foreign;
\* notes/holder-actors.md Foreign keysets). Three things: T above U above B
\* (U holds read on T, B on U). B is fixed: its keysets and which nodes hold
\* each invalid. U and T rotate; a box of T to U names keysets of U, a box of
\* U to B (its own rotation's, the one Foreign reads) keysets of B.
\* Scen "fork": ForkRot's mixed case one level down. B is forked for good
\* (p's keyset bP invalid at q, q's bQ at p); p and q both admins of U and T
\* (their rights on U and T direct, so U's and T's epochs valid on both sides).
\* Scen "race": the honest race of notes/holder-actors.md. Party X removed from
\* U, which m (U's admin, reading U) knows and w (T's writer, not reading U)
\* never learns but through U's keysets (a reader's removal travels nowhere);
\* B's keyset kn made by a party a concurrent demotion invalidates, held
\* invalid where the demotion is (U's keysets made knowing it carry it).
\* Above: how T judges a foreign keyset of U. "drop": as held invalid (its
\* list passes nothing on); "builder": as any held valid keyset; "star" (the
\* rule): its list keeps what it lists stale, but it anchors nothing and is no
\* Seal candidate (a stale keyset Seal then gives is blocked). ListForeign: a
\* rotation's keyset lists every current epoch (TRUE) or only those not
\* foreign at its maker (FALSE, the rule; its history box carries every
\* current one, which supersedes at holders of its secret).
\* Unprompted rotations (any departure's) MaxU of U and MaxT of T per
\* rotator. Left-out records stand while held (their causes are rotation
\* commits). Every node holds every secret of T; U's rotators U's. Commits
\* arrive in causal order (a rotation after what it lists), an epoch of T or
\* a re-seal with the keysets of U it names and their history (Carried).
\* RekeyLists: U's rotator judges which keysets of U are current for the
\* re-key (Left out) by the lists of keysets not foreign alone (TRUE: a
\* foreign keyset, listed nowhere, stays current for good), or as CurU, its
\* history boxes counted at a holder of their secret (FALSE, the rule).
\* Box removal: a rotation of T removes the boxes (its own and re-seals') at
\* each epoch it lists or carries in its history box (every node holds every
\* secret of T), from the state every node shares, a foreign one's included.
\* Anchors and re-seals read the state. StaleKept: Stale reads every box
\* written at an epoch, removed or not (TRUE, the rule: spec/crypto.md \S 4
\* Stale); FALSE (control): the state's boxes alone, so a rotation foreign at
\* a node strips the box that kept an epoch still current there stale.
EXTENDS Naturals, FiniteSets

CONSTANTS Scen, Above, ListForeign, RekeyLists, StaleKept, MaxU, MaxT, QU, QT

Nodes == IF Scen = "fork" THEN {"p", "q"} ELSE {"m", "w"}
RotU == IF Scen = "fork" THEN {"p", "q"} ELSE {"m"}
RotT == IF Scen = "fork" THEN {"p", "q"} ELSE {"w"}
SecU(s) == s \in RotU
KnowsX(s) == Scen = "race" /\ s = "m"

\* B's keysets: by, lists
B == IF Scen = "fork"
     THEN [i \in 1..3 |-> IF i = 1 THEN [by |-> "0", lists |-> {}]
                          ELSE IF i = 2 THEN [by |-> "p", lists |-> {1}]
                          ELSE [by |-> "q", lists |-> {1}]]
     ELSE [i \in 1..2 |-> IF i = 1 THEN [by |-> "0", lists |-> {}]
                          ELSE [by |-> "P", lists |-> {1}]]

VARIABLES u,   \* U's epochs: index -> [by, lists, hist, box, knows, dem, ht]
          t,   \* T's epochs: index -> [by, lists, hist, box, rec, ht]
          rs,  \* re-seals of U into T's epochs: [e, ks, by]
          hu, ht, hr, hd,  \* per node: U's epochs, T's, re-seals, the demotion held
          nu, nt, uu, ut,  \* per rotator: rotations of U, of T, unprompted ones
          wr               \* T's content writes: [e, knew]

vars == <<u, t, rs, hu, ht, hr, hd, nu, nt, uu, ut, wr>>

Len(f) == Cardinality(DOMAIN f)
Ext(f, x) == [i \in 1..Len(f) + 1 |-> IF i <= Len(f) THEN f[i] ELSE x]
Max(S) == IF S = {} THEN 0 ELSE CHOOSE h \in S : \A g \in S : g <= h

\* ---- B
InvB(s, b) == IF Scen = "fork" THEN B[b].by \notin {"0", s} ELSE b = 2 /\ hd[s]
StaleB(s, b) == InvB(s, b) \/ \E c \in DOMAIN B : ~InvB(s, c) /\ b \in B[c].lists
BSeal(s) == {b \in DOMAIN B : ~StaleB(s, b)}

\* ---- U at its own level
ForU(s, k) == \E b \in u[k].box : InvB(s, b)
StaleBoxU(s, k) == \E b \in u[k].box : StaleB(s, b)
SupU(s, j) == IF ForU(s, j) THEN {} ELSE u[j].lists \cup (IF SecU(s) THEN u[j].hist ELSE {})
CurU(s) == {k \in hu[s] : ~\E j \in hu[s] : k \in SupU(s, j)}
CovU(s, k) == ~KnowsX(s) \/ u[k].knows
BlkU(s, k) == StaleBoxU(s, k) \/ ~CovU(s, k)

\* ---- U as T sees it
VAbove(s, k) == Above # "drop" \/ ~ForU(s, k)
AnchorOK(s, k) == IF Above = "builder" THEN TRUE ELSE ~ForU(s, k)
StaleAbove(s, k) == ~VAbove(s, k) \/ \E j \in hu[s] : VAbove(s, j) /\ k \in u[j].lists
RECURSIVE AncU(_, _)
AncU(s, k) == IF ~VAbove(s, k) THEN {}
              ELSE LET l == u[k].lists \cap hu[s] IN l \cup UNION {AncU(s, j) : j \in l}

\* ---- T
ForT(s, e) == \E k \in t[e].box : ForU(s, k)
SupT(s, j) == IF ForT(s, j) THEN {} ELSE t[j].lists \cup t[j].hist
CurT(s) == {e \in ht[s] : ~\E j \in ht[s] : e \in SupT(s, j)}
RecsAt(s) == UNION {t[e].rec : e \in CurT(s)}
LeftU(s, k) == k \in RecsAt(s) /\ VAbove(s, k)
BlkAbove(s, k) == StaleAbove(s, k) \/ StaleBoxU(s, k) \/ ~CovU(s, k) \/ LeftU(s, k)
\* every box written at e that s holds; those of the state: less those a held
\* rotation of T listing e or carrying it in its history box removed (e's own
\* box, and each re-seal made before that rotation: r.at epochs of T then)
BoxesT(s, e) == {S \in {t[e].box} \cup {r.ks : r \in {x \in hr[s] : x.e = e}} : S # {}}
RemovedBy(s, e) == {j \in ht[s] : e \in t[j].lists \cup t[j].hist}
StateT(s, e) == {S \in (IF RemovedBy(s, e) = {} THEN {t[e].box} ELSE {})
                       \cup {r.ks : r \in {x \in hr[s] : x.e = e /\ \A j \in RemovedBy(s, e) : x.at >= j}} : S # {}}
StaleT(s, e) == IF StaleKept THEN BoxesT(s, e) ELSE StateT(s, e)
BlkT(s, e) == \E S \in StaleT(s, e) : \E k \in S : BlkAbove(s, k)
KnowDueT(s, e) == ~ForT(s, e) /\ \E S \in StaleT(s, e) : \E k \in S : StaleAbove(s, k)
RotTDue(s) == (\A e \in CurT(s) : BlkT(s, e)) \/ \E e \in CurT(s) : KnowDueT(s, e)

Cand(s) == {k \in hu[s] : AnchorOK(s, k)}
Anchors(s) == {k \in UNION UNION {StateT(s, e) : e \in CurT(s)} : k \in Cand(s)}
Newest(S) == CHOOSE k \in S : \A j \in S : u[j].ht < u[k].ht \/ (u[j].ht = u[k].ht /\ j <= k)
From(s, a) == {k \in Cand(s) : k = a \/ a \in AncU(s, k)}
SealSet(s) ==
  LET as == Anchors(s)
      all == {k \in Cand(s) : \A a \in as : k = a \/ a \in AncU(s, k)}
      tops == {a \in as : ~\E b \in as : a \in AncU(s, b)}
  IN IF all # {} THEN {Newest(all)}
     ELSE IF \E a \in tops : From(s, a) = {} THEN {}
     ELSE {Newest(From(s, a)) : a \in tops}
SealOK(s) == SealSet(s) # {} /\ \A k \in SealSet(s) : ~BlkAbove(s, k)
ResealAt(s) == {e \in CurT(s) : StateT(s, e) = {}}
CanReseal(s) == SealOK(s) /\ \E e \in ResealAt(s) : [e |-> e, ks |-> SealSet(s), by |-> s, at |-> Len(t)] \notin rs

CurUL(s) == {k \in hu[s] : ~\E j \in hu[s] : ~ForU(s, j) /\ k \in u[j].lists}
RotUDue(s) == \/ \E k \in CurU(s) : ~ForU(s, k) /\ BlkU(s, k)
              \/ \A k \in CurU(s) : BlkU(s, k)
              \/ \E k \in IF RekeyLists THEN CurUL(s) ELSE CurU(s) : LeftU(s, k)

Lists(cur, foreign(_)) == IF ListForeign THEN cur ELSE {x \in cur : ~foreign(x)}

RotUAct(s) ==
  /\ s \in RotU
  /\ RotUDue(s) \/ uu[s] < MaxU
  /\ uu' = [uu EXCEPT ![s] = IF RotUDue(s) THEN @ ELSE @ + 1]
  /\ LET fr(k) == ForU(s, k) IN
     u' = Ext(u, [by |-> s, lists |-> Lists(CurU(s), fr), hist |-> CurU(s), box |-> BSeal(s),
                  knows |-> TRUE, dem |-> hd[s], ht |-> 1 + Max({u[j].ht : j \in CurU(s)})])
  /\ hu' = [hu EXCEPT ![s] = @ \cup {Len(u) + 1}]
  /\ nu' = [nu EXCEPT ![s] = @ + 1]
  /\ UNCHANGED <<t, rs, ht, hr, hd, nt, ut, wr>>

RotTAct(s) ==
  /\ s \in RotT
  /\ s \notin RotU \/ ~RotUDue(s)   \* rotations due are made bottom-up
  /\ RotTDue(s) \/ ut[s] < MaxT
  /\ ut' = [ut EXCEPT ![s] = IF RotTDue(s) THEN @ ELSE @ + 1]
  /\ LET out == ~SealOK(s)
         fr(e) == ForT(s, e)
     IN t' = Ext(t, [by |-> s, lists |-> Lists(CurT(s), fr), hist |-> CurT(s),
                     box |-> IF out THEN {} ELSE SealSet(s),
                     rec |-> IF out THEN {k \in CurU(s) : VAbove(s, k) /\ BlkAbove(s, k)} \cup RecsAt(s) ELSE {},
                     ht |-> 1 + Max({t[j].ht : j \in CurT(s)})])
  /\ ht' = [ht EXCEPT ![s] = @ \cup {Len(t) + 1}]
  /\ nt' = [nt EXCEPT ![s] = @ + 1]
  /\ UNCHANGED <<u, rs, hu, hr, hd, nu, uu, wr>>

Reseal(s) ==
  /\ s \in RotT /\ SealOK(s)
  /\ \E e \in ResealAt(s) :
       LET r == [e |-> e, ks |-> SealSet(s), by |-> s, at |-> Len(t)] IN
       /\ r \notin rs
       /\ rs' = rs \cup {r}
       /\ hr' = [hr EXCEPT ![s] = @ \cup {r}]
  /\ UNCHANGED <<u, t, hu, ht, hd, nu, nt, uu, ut, wr>>

\* a writer of T writes (the race's leak check): what is due rotated first
Write(s) ==
  /\ Scen = "race" /\ s \in RotT /\ ~RotTDue(s)
  /\ \E e \in CurT(s) :
       /\ ~BlkT(s, e) /\ ~ForT(s, e)
       /\ wr' = wr \cup {[e |-> e, knew |-> \E k \in hu[s] : u[k].knows]}
  /\ UNCHANGED <<u, t, rs, hu, ht, hr, hd, nu, nt, uu, ut>>

RECURSIVE HistU(_)
HistU(S) == LET X == S \cup UNION {u[k].hist \cup u[k].lists : k \in S} IN IF X = S THEN S ELSE HistU(X)
Dem(K) == \E k \in K : u[k].dem
\* commits arrive in causal order: a rotation after the epochs it lists
DeliverU(s) == \E k \in (1..Len(u)) \ hu[s] :
  /\ u[k].lists \cup u[k].hist \subseteq hu[s]
  /\ hu' = [hu EXCEPT ![s] = @ \cup {k}]
  /\ hd' = [hd EXCEPT ![s] = @ \/ u[k].dem]
  /\ UNCHANGED <<u, t, rs, ht, hr, nu, nt, uu, ut, wr>>
\* an epoch of T arrives with the keysets of U it names (Carried)
DeliverT(s) == \E e \in (1..Len(t)) \ ht[s] :
  /\ t[e].lists \cup t[e].hist \subseteq ht[s]
  /\ ht' = [ht EXCEPT ![s] = @ \cup {e}]
  /\ hu' = [hu EXCEPT ![s] = @ \cup HistU(t[e].box \cup t[e].rec)]
  /\ hd' = [hd EXCEPT ![s] = @ \/ Dem(HistU(t[e].box \cup t[e].rec))]
  /\ UNCHANGED <<u, t, rs, hr, nu, nt, uu, ut, wr>>
DeliverR(s) == \E r \in rs \ hr[s] :
  /\ r.e \in ht[s]
  /\ hr' = [hr EXCEPT ![s] = @ \cup {r}]
  /\ hu' = [hu EXCEPT ![s] = @ \cup HistU(r.ks)]
  /\ hd' = [hd EXCEPT ![s] = @ \/ Dem(HistU(r.ks))]
  /\ UNCHANGED <<u, t, rs, ht, nu, nt, uu, ut, wr>>
DeliverD(s) ==
  /\ Scen = "race" /\ ~hd[s]
  /\ hd' = [hd EXCEPT ![s] = TRUE]
  /\ UNCHANGED <<u, t, rs, hu, ht, hr, nu, nt, uu, ut, wr>>

Init ==
  /\ u = [i \in {1} |-> [by |-> "0", lists |-> {}, hist |-> {}, box |-> {1},
                         knows |-> Scen = "fork", dem |-> FALSE, ht |-> 0]]
  /\ t = [i \in {1} |-> [by |-> "0", lists |-> {}, hist |-> {}, box |-> {1}, rec |-> {}, ht |-> 0]]
  /\ rs = {}
  /\ hu = [s \in Nodes |-> {1}]
  /\ ht = [s \in Nodes |-> {1}]
  /\ hr = [s \in Nodes |-> {}]
  /\ hd = [s \in Nodes |-> FALSE]
  /\ nu = [s \in Nodes |-> 0]
  /\ nt = [s \in Nodes |-> 0]
  /\ uu = [s \in Nodes |-> 0]
  /\ ut = [s \in Nodes |-> 0]
  /\ wr = {}

Next == \E s \in Nodes :
          \/ RotUAct(s) \/ RotTAct(s) \/ Reseal(s) \/ Write(s)
          \/ DeliverU(s) \/ DeliverT(s) \/ DeliverR(s) \/ DeliverD(s)

Spec == Init /\ [][Next]_vars

\* NoLeak: X, removed from U, opens no content of T written by a writer
\* holding a keyset of U made knowing the removal (through T's histories too)
XHolds == {k \in DOMAIN u : ~u[k].knows}
AllBoxesT(e) == {S \in {t[e].box} \cup {r.ks : r \in {x \in rs : x.e = e}} : S # {}}
RECURSIVE HistT(_)
HistT(S) == LET X == S \cup UNION {t[e].hist \cup t[e].lists : e \in S} IN IF X = S THEN S ELSE HistT(X)
XReads(e) == \E e2 \in DOMAIN t : (\E S \in AllBoxesT(e2) : S \subseteq XHolds) /\ e \in HistT({e2})
NoLeak == \A c \in wr : c.knew => ~XReads(c.e)

\* Quiet: rotations stop (bounded by the fork's own events and the unprompted ones)
Quiet == \A s \in Nodes : nu[s] <= QU /\ nt[s] <= QT

AllHeld == \A s \in Nodes : hu[s] = DOMAIN u /\ ht[s] = DOMAIN t /\ hr[s] = rs /\ (Scen = "race" => hd[s])
Due == \E s \in Nodes : \/ s \in RotU /\ (RotUDue(s) \/ uu[s] < MaxU)
                        \/ s \in RotT /\ (RotTDue(s) \/ ut[s] < MaxT \/ CanReseal(s))
Settled == AllHeld /\ ~Due
\* Live: settled, each writer of T writes under an epoch boxing U at keysets
\* its side applies, and each rotator of U holds an unblocked epoch of U
Live == Settled =>
          /\ \A s \in RotT : \E e \in CurT(s) :
               ~BlkT(s, e) /\ ~ForT(s, e) /\ \E S \in StateT(s, e) : \A k \in S : ~ForU(s, k)
          /\ \A s \in RotU : \E k \in CurU(s) : ~BlkU(s, k)
\* Kept: settled, every epoch of T is current at each writer or in the
\* history of a current one; alike for U at its rotators
Kept == Settled =>
          /\ \A s \in RotT : DOMAIN t \subseteq HistT(CurT(s))
          /\ \A s \in RotU : DOMAIN u \subseteq HistU(CurU(s))
\* probe: an epoch current at a writer of T, not foreign there, whose every box
\* a rotation removed (expected reachable: a rotation foreign at the writer)
ProbeStrip == ~\E s \in RotT : \E e \in CurT(s) : ~ForT(s, e) /\ BoxesT(s, e) # {} /\ StateT(s, e) = {}
====

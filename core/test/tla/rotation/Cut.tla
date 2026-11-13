--------------------------------- MODULE Cut ---------------------------------
(* History cuts (issues/history-less-grant.md): a grant without history is a *)
(* read rotation at the grant (the cut) whose history box carries no earlier *)
(* secret. One actor, one key role. Admins rotate, grant, re-seal, remove    *)
(* and rotate over forks (Merge, by a); readers only add history. CutTo are *)
(* granted without history (m: removed, then re-added without history),     *)
(* HistTo with history (one in CutTo too: showing history later).           *)
(* The rule (Rule = "cut"): each keyset carries a floor, the n of the newest *)
(* cut it descends from (a cut: its own n; else the greatest floor of the   *)
(* epochs it lists), at most its own n (above it the keyset is invalid). A *)
(* node reads a floor as at least the floor of each epoch it lists that it  *)
(* holds. A history entry at e carries f only when f's floor is at least    *)
(* e's and at least the floor of e's maker (rotations, grants, re-seals and *)
(* adds alike). A party's floor is its newest grant's: a cut's n; a grant   *)
(* with history, its author's floor. A holder is boxed (rotation, grant,    *)
(* re-seal) at e only when e's floor is at least its floor. An epoch some   *)
(* held rotation lists but may not carry is dropped; a grant with history   *)
(* boxes the grantee at each dropped epoch it holds, and any holder of a    *)
(* dropped epoch boxes it to a holder allowed it that the holder cannot     *)
(* open from the live boxes (the tip add). A rotation places again,         *)
(* projected to their roles.0 deltas and under its own epoch, the role      *)
(* commits it holds wrapped only under epochs below its floor (Replace). m's *)
(* re-add also boxes m at each epoch its removal's rotation listed (a new   *)
(* node of a member opens what its other nodes do).                         *)
(* Hostile parties (a writer, history-less or not) rotate with any listing  *)
(* of the epochs they know of and any floor the validity rule lets through; *)
(* the rest of their rotation follows the rules from that keyset (what else *)
(* a holder hands out is its own to hand). A hostile history-less admin     *)
(* grants Accomp with history.                                              *)
(* Controls: "old" (no floor: adds, grants, re-seals and rotations carry any *)
(* earlier secret, boxing ignores grants' cuts), "nocarry" (the carry rule   *)
(* off), "nofloor" (the boxing rule off), "oldadd" (the History add as   *)
(* before: any earlier secret; the rest as the rule), "nomaker" (the carry *)
(* rule judges e's floor alone), "nogfloor" (a grant with history gives     *)
(* floor 0 whoever writes it), "nolist" (floors read as written), "nocap"   *)
(* (a floor above n is valid), "noreadd" (m's re-add boxes only at the   *)
(* cut); Replace FALSE.                                                     *)
(* Commits arrive in any order a node can read them: wrapped under an epoch *)
(* it holds, boxing it, granting it, or placed again under a cut it holds.   *)
(* Box removal is observed-remove: a rotation removes the boxes it holds at *)
(* the epochs its history box carries. Know(x): every secret x ever opens  *)
(* (all boxes and entries ever written); Fresh(x): what a new node of x     *)
(* opens from the live state.                                               *)
EXTENDS Naturals, FiniteSets

CONSTANTS Rule, Replace, Admins, Readers, CutTo, HistTo, RemoveM, MaxRot, MaxMerge, MaxDue, MaxC,
          Hostile, Accomp, MaxHost, HiF

M == "m"
InitH == Admins \cup Readers \cup (IF RemoveM THEN {M} ELSE {})
Parties == InitH \cup CutTo \cup HistTo
Honest == Parties \ (Hostile \cup Accomp)
\* the rule, or one of its parts off that adds to the floor rules (the rest are older controls)
RuleOn == Rule \in {"cut", "nomaker", "nogfloor", "nolist", "nocap", "noreadd"}

Base == [ep |-> FALSE, n |-> 0, floor |-> 0, cut |-> FALSE, by |-> "a", lists |-> {},
         ents |-> {}, boxes |-> {}, unbox |-> {}, names |-> {}, knows |-> {}, rm |-> "",
         gr |-> "", hist |-> FALSE, replace |-> {}, wraps |-> {}]
E0 == [Base EXCEPT !.ep = TRUE, !.boxes = {<<x, 0>> : x \in InitH}, !.ents = {<<0, {}>>}, !.wraps = {0}]

VARIABLES C,      \* commit id -> commit (a rotation is an epoch, its id the epoch's)
          held,   \* node -> commit ids it holds
          proj,   \* node -> commit ids it holds projected to their roles.0 delta (placed again)
          nrot, nmerge, ndue, nhost
vars == <<C, held, proj, nrot, nmerge, ndue, nhost>>

Ids == DOMAIN C
EIds == {i \in Ids : C[i].ep}
K == Cardinality(Ids) + 1
Max(S) == CHOOSE x \in S : \A y \in S : y <= x
Min(S) == CHOOSE x \in S : \A y \in S : x <= y

\* ---- secrets ----------------------------------------------------------------
RECURSIVE Close(_, _, _)
Close(S, E, k) == LET T == S \cup UNION {y[2] : y \in {z \in E : z[1] \in S}}
                  IN IF T = S \/ k = 0 THEN T ELSE Close(T, E, k - 1)
EntsIn(I) == UNION {C[i].ents : i \in I}
BoxesIn(x, I) == {b[2] : b \in {bb \in UNION {C[i].boxes : i \in I} : bb[1] = x}}
Removed(x, e, i) == \E j \in Ids : <<x, e, i>> \in C[j].unbox
LiveTo(x) == {e \in EIds : \E i \in Ids : <<x, e>> \in C[i].boxes /\ ~Removed(x, e, i)}

\* what node v opens from what it holds
Sec(v) == Close(BoxesIn(v, held[v]), EntsIn(held[v]), K)
\* every secret x ever obtains (any box or entry ever written: conservative)
Know(x) == Close(BoxesIn(x, Ids), EntsIn(Ids), K)
\* what a new node of x opens from the live state
Fresh(x) == Close(LiveTo(x), EntsIn(Ids), K)


\* ---- rosters ----------------------------------------------------------------
RmHeld(v, x) == \E i \in held[v] \cup proj[v] : C[i].rm = x
GrHeld(v, x) == \E i \in held[v] \cup proj[v] : C[i].gr = x
Holders(v) == {x \in InitH : ~RmHeld(v, x) \/ GrHeld(v, x)} \cup {x \in Parties \ InitH : GrHeld(v, x)}
Departed(v) == {x \in Parties : RmHeld(v, x)} \ Holders(v)
GrantsOf(v, x) == {i \in held[v] \cup proj[v] : C[i].gr = x}
\* a grant's floor: a cut's n; with history, its author's floor (one level: authors are granted
\* without history or not at all)
AuthFloor(v, y) == LET gs == GrantsOf(v, y) IN IF gs = {} THEN 0 ELSE Min({IF C[i].cut THEN C[i].n ELSE 0 : i \in gs})
GFloor(v, i) == IF C[i].cut THEN C[i].n ELSE IF Rule = "nogfloor" THEN 0 ELSE AuthFloor(v, C[i].by)
\* x's floor at v: its newest grant's (here the least: a party is cut once, and granted with
\* history at most once, after)
FloorOf(v, x) ==
  IF Rule = "old" \/ Rule = "nofloor" THEN 0
  ELSE LET gs == GrantsOf(v, x) IN IF gs = {} THEN 0 ELSE Min({GFloor(v, i) : i \in gs})
Allowed(v, x, fl) == fl >= FloorOf(v, x)
\* e's floor as v reads it: at least the floor of each epoch it lists that v holds
RECURSIVE RFl(_, _, _)
RFl(v, e, k) == IF Rule = "nolist" \/ k = 0 THEN C[e].floor
                ELSE Max({C[e].floor} \cup {RFl(v, f, k - 1) : f \in C[e].lists \cap held[v]})
Fl(v, e) == RFl(v, e, K)
\* f may be carried in a history entry of floor fl at an epoch made by mk
CarryOK(v, f, fl, mk) == Rule = "old" \/ Rule = "nocarry"
                         \/ (Fl(v, f) >= fl /\ (Rule = "nomaker" \/ Fl(v, f) >= FloorOf(v, mk)))

\* ---- epochs at a node ---------------------------------------------------------
\* established: held, and where v holds its secret, the removals it names held
Est(v) == {e \in held[v] \cap EIds : e \in Sec(v) => C[e].names \subseteq held[v] \cup proj[v]}
\* current: as the spec, less the epochs below v's own floor (v is never boxed them: held, their
\* commits show only an epoch whose superseding chain v cannot read, e.g. a re-added m's removal)
Cur(v) == {e \in Est(v) : (~RuleOn \/ Allowed(v, v, Fl(v, e))) /\ ~\E f \in Est(v) : e \in C[f].lists}
Unsup(v) == {e \in held[v] \cap EIds : ~\E f \in held[v] \cap EIds : e \in C[f].lists}
Mine(v) == Sec(v) \cap Est(v)
\* what v, from what it holds, sees x open from the live boxes (a box removal counts once its
\* rotation is established)
ViewFresh(v, x) ==
  Close({e \in EIds : \E i \in held[v] : <<x, e>> \in C[i].boxes
                       /\ ~\E j \in Est(v) : <<x, e, i>> \in C[j].unbox},
        EntsIn(held[v]), K)
Covers(v, e) == e \in Sec(v) /\ Departed(v) \subseteq C[e].knows
Due(v) == Departed(v) # {} /\ \E e \in Cur(v) : ~Covers(v, e)
ListedAt(v, e) == UNION {y[2] : y \in {z \in EntsIn(held[v]) : z[1] = e}}
\* epochs a held rotation lists but may not carry
Dropped(v) == {f \in Mine(v) : \E e \in held[v] \cap EIds : f \in C[e].lists /\ ~CarryOK(v, f, Fl(v, e), C[e].by)}
\* the superset entry a grant or re-seal writes at e (only what is listed where e is blocked)
Superset(v, e) == ListedAt(v, e) \cup
  IF Covers(v, e) THEN {f \in Mine(v) \ Cur(v) : C[f].n < C[e].n /\ CarryOK(v, f, Fl(v, e), C[e].by)} ELSE {}

\* a commit is valid at v once v holds its author's grant (validity reads the author's role)
Valid(v, i) == C[i].by \in InitH \/ C[i].by = v \/ GrHeld(v, C[i].by)
Readable(v, i) ==
  /\ Valid(v, i)
  /\ \/ C[i].wraps \cap Sec(v) # {}
     \/ \E b \in C[i].boxes : b[1] = v
     \/ C[i].gr = v
\* a named commit placed again under a cut v holds: its roles.0 delta alone
Projectable(v, i) == i \notin held[v] \cup proj[v] /\ \E d \in held[v] \cap EIds : i \in C[d].replace /\ d \in Sec(v)

Add(c) == LET id == Cardinality(Ids)
          IN /\ C' = [i \in Ids \cup {id} |-> IF i = id THEN c ELSE C[i]]
             /\ held' = [held EXCEPT ![c.by] = @ \cup {id}]
             /\ UNCHANGED proj

\* a rotation by v listing ls, of n and floor fl; cut: a grant to gr without history; rm: a removal
Rot(v, ls, n, fl, cut, gr, rm) ==
  LET id == Cardinality(Ids)
      carry == IF cut THEN {} ELSE {f \in Mine(v) : CarryOK(v, f, fl, v)}
      hs == ((Holders(v) \ {rm}) \cup (IF gr = "" THEN {} ELSE {gr}))
      boxed == {x \in hs : x = gr \/ x = v \/ Allowed(v, x, fl)}
      names == {i \in held[v] \cup proj[v] : C[i].rm # ""}
      \* the role commits v holds wrapped only under epochs below the new floor
      again == {i \in held[v] \cup proj[v] : (C[i].rm # "" \/ C[i].gr # "") /\ \A w \in C[i].wraps : Fl(v, w) < fl}
      \* m's re-add: a box at each epoch its removal's rotation (held whole) listed that v opens
      readd == IF gr = M /\ Rule # "noreadd" THEN UNION {C[i].lists \cap Sec(v) : i \in {j \in held[v] : C[j].rm = M}} ELSE {}
  IN [Base EXCEPT !.ep = TRUE, !.n = n, !.floor = fl, !.cut = cut, !.by = v, !.lists = ls,
        !.ents = {<<id, carry>>}, !.boxes = {<<x, id>> : x \in boxed} \cup {<<M, e>> : e \in readd},
        \* the boxes it holds at the epochs it carries
        !.unbox = UNION {{<<b[1], b[2], i>> : b \in {bb \in C[i].boxes : bb[2] \in carry}} : i \in held[v]},
        !.names = names, !.knows = Departed(v) \cup (IF rm = "" THEN {} ELSE {rm}),
        !.rm = rm, !.gr = gr, !.replace = IF Replace THEN again ELSE {},
        !.wraps = ls \cap Sec(v)]
NewRot(v, cut, gr, rm) ==
  LET ls == Cur(v) \cup Unsup(v)
      n == Max({C[e].n : e \in ls}) + 1
  IN Rot(v, ls, n, IF cut THEN n ELSE Max({Fl(v, e) : e \in ls}), cut, gr, rm)

MayRotate(v) == v \in Admins /\ v \in Holders(v) /\ Sec(v) # {}
Granted(x) == \E i \in Ids : C[i].gr = x
HistGranted(x) == \E i \in Ids : C[i].gr = x /\ C[i].hist
CutGranted(x) == \E i \in Ids : C[i].gr = x /\ C[i].cut

\* ---- actions ----------------------------------------------------------------
Rotate(v) == /\ MayRotate(v) /\ nrot < MaxRot
             /\ Add(NewRot(v, FALSE, "", "")) /\ nrot' = nrot + 1 /\ UNCHANGED <<nmerge, ndue, nhost>>
\* a rotates while it holds a fork (any rotation lists every current epoch)
Merge(v) == /\ v = "a" /\ MayRotate(v) /\ Cardinality(Cur(v)) > 1 /\ nmerge < MaxMerge
            /\ Add(NewRot(v, FALSE, "", "")) /\ nmerge' = nmerge + 1 /\ UNCHANGED <<nrot, ndue, nhost>>
\* the knowing re-key: a current epoch misses a departure v knows (or v lacks its secret)
DueRot(v) == /\ MayRotate(v) /\ Due(v) /\ ndue < MaxDue
             /\ Add(NewRot(v, FALSE, "", "")) /\ ndue' = ndue + 1 /\ UNCHANGED <<nrot, nmerge, nhost>>
\* a grant without history (m: its re-add, by a node holding its removal)
CutGrant(v, x) ==
  /\ MayRotate(v) /\ x \in CutTo /\ ~CutGranted(x)
  /\ IF x = M THEN RmHeld(v, M) /\ M \notin Holders(v) ELSE x \notin Holders(v)
  /\ Add(NewRot(v, TRUE, x, "")) /\ UNCHANGED <<nrot, nmerge, ndue, nhost>>
\* a grant with history: boxes at the current epochs v holds (with their superset entries) and
\* at each dropped epoch it holds (showing history later: after its cut); Accomp only by a hostile
\* party
HistGrant(v, x) ==
  /\ x \in HistTo /\ ~HistGranted(x)
  /\ IF x \in Accomp THEN v \in Hostile /\ v \in Holders(v) /\ Sec(v) # {} ELSE MayRotate(v)
  /\ (x \in CutTo => GrHeld(v, x))
  /\ LET cur == Cur(v) \cap Sec(v)
         at == cur \cup (IF RuleOn THEN Dropped(v) ELSE {})
     IN Add([Base EXCEPT !.by = v, !.gr = x, !.hist = TRUE, !.boxes = {<<x, e>> : e \in at},
               !.ents = {<<e, Superset(v, e)>> : e \in cur}, !.wraps = cur])
  /\ UNCHANGED <<nrot, nmerge, ndue, nhost>>
\* the removal of m, with its rotation
Remove(v) == /\ RemoveM /\ MayRotate(v) /\ M \in Holders(v) /\ ~\E i \in Ids : C[i].rm = M
             /\ Add(NewRot(v, FALSE, "", M)) /\ UNCHANGED <<nrot, nmerge, ndue, nhost>>
\* a re-seal of a current holder lacking a box at a current epoch v holds
Reseal(v, x, e) ==
  /\ MayRotate(v) /\ x \in Holders(v) \ {v} /\ e \in Cur(v) \cap Sec(v)
  /\ ~\E i \in held[v] : <<x, e>> \in C[i].boxes
  /\ Allowed(v, x, Fl(v, e))
  /\ Add([Base EXCEPT !.by = v, !.boxes = {<<x, e>>}, !.ents = {<<e, Superset(v, e)>>}, !.wraps = {e}])
  /\ UNCHANGED <<nrot, nmerge, ndue, nhost>>
\* History add: a holder holding an established superseded secret that no entry at a current
\* epoch it holds lists, and that the carry rule lets in
AddMissing(v, e) == {f \in Mine(v) \ Cur(v) : C[f].n < C[e].n
                      /\ (Rule = "oldadd" \/ CarryOK(v, f, Fl(v, e), C[e].by))} \ ListedAt(v, e)
AddDue(v, e) == v \in Holders(v) /\ e \in Cur(v) /\ Covers(v, e) /\ AddMissing(v, e) # {}
HistAdd(v, e) ==
  /\ AddDue(v, e)
  /\ Add([Base EXCEPT !.by = v, !.ents = {<<e, AddMissing(v, e)>>}, !.wraps = {e}])
  /\ UNCHANGED <<nrot, nmerge, ndue, nhost>>
\* tip add: a holder of a dropped epoch boxes it to a holder allowed it that, as v sees it,
\* cannot open it from the live boxes
TipDue(v, x, t) == /\ RuleOn /\ v \in Holders(v) /\ x \in Holders(v) \ {v}
                   /\ t \in Dropped(v) /\ Allowed(v, x, Fl(v, t)) /\ t \notin ViewFresh(v, x)
TipAdd(v, x, t) ==
  /\ TipDue(v, x, t)
  /\ Add([Base EXCEPT !.by = v, !.boxes = {<<x, t>>}, !.wraps = Cur(v) \cap Sec(v)])
  /\ UNCHANGED <<nrot, nmerge, ndue, nhost>>
\* the attacker: a hostile writer rotates listing any epochs it knows of, with any floor the
\* validity rule lets through (at most n; "nocap": up to HiF above)
Known(v) == (held[v] \cap EIds) \cup UNION {C[e].lists : e \in held[v] \cap EIds}
HostRot(h) ==
  /\ h \in Hostile /\ h \in Holders(h) /\ Sec(h) # {} /\ nhost < MaxHost
  /\ \E ls \in SUBSET Known(h) \ {{}} :
       LET n == Max({C[e].n : e \in ls}) + 1
       IN \E fl \in 0..(n + (IF Rule = "nocap" THEN HiF ELSE 0)) : Add(Rot(h, ls, n, fl, FALSE, "", ""))
  /\ nhost' = nhost + 1 /\ UNCHANGED <<nrot, nmerge, ndue>>

Deliver(v) == \E i \in Ids \ held[v] : Readable(v, i) /\ held' = [held EXCEPT ![v] = @ \cup {i}]
              /\ UNCHANGED <<C, proj, nrot, nmerge, ndue, nhost>>
DeliverProj(v) == \E i \in Ids : Projectable(v, i) /\ proj' = [proj EXCEPT ![v] = @ \cup {i}]
                  /\ UNCHANGED <<C, held, nrot, nmerge, ndue, nhost>>

Init == /\ C = [i \in {0} |-> E0]
        /\ held = [v \in Parties |-> IF v \in InitH THEN {0} ELSE {}]
        /\ proj = [v \in Parties |-> {}]
        /\ nrot = 0 /\ nmerge = 0 /\ ndue = 0 /\ nhost = 0

Next == \/ \E v \in Admins : Rotate(v) \/ Merge(v) \/ DueRot(v) \/ Remove(v)
                             \/ (\E x \in CutTo : CutGrant(v, x)) \/ (\E x \in HistTo : HistGrant(v, x))
                             \/ (\E x \in Parties, e \in EIds : Reseal(v, x, e))
        \/ \E h \in Hostile : HostRot(h) \/ \E x \in Accomp : HistGrant(h, x)
        \/ \E v \in Parties, e \in EIds : HistAdd(v, e)
        \/ \E v \in Parties, x \in Parties, t \in EIds : TipAdd(v, x, t)
        \/ \E v \in Parties : Deliver(v) \/ DeliverProj(v)

Spec == Init /\ [][Next]_vars
\* the search bound on commits (a state at it is cut short: Settled needs nothing more due)
Bound == Cardinality(Ids) <= MaxC

\* ---- properties -------------------------------------------------------------
RECURSIVE AncC(_, _)
AncC(S, k) == LET T == S \cup UNION {C[f].lists : f \in S} IN IF T = S \/ k = 0 THEN T ELSE AncC(T, k - 1)
\* the epochs in e's causal past (its rotator held them: it listed them or what superseded them)
Anc(e) == AncC(C[e].lists, K)
Desc(e) == {f \in EIds : e \in Anc(f)}
CutOf(x) == CHOOSE i \in Ids : C[i].gr = x /\ C[i].cut
RmC == CHOOSE i \in Ids : C[i].rm = M
HasRm == \E i \in Ids : C[i].rm = M
\* what the hostile parties obtain (what they may hand anyone)
HKnow == UNION {Know(y) : y \in Hostile \cup Accomp}

\* a holder granted without history (and never with) obtains no secret of an epoch in its grant's
\* causal past, by any path: none at all for a hostile one and what it grants with history; for an
\* honest one, none but what a hostile party holds (it may box anyone with that)
NoPast == /\ \A x \in (CutTo \ InitH) : CutGranted(x) /\ ~HistGranted(x) =>
               Know(x) \cap Anc(CutOf(x)) \subseteq (IF x \in Hostile THEN {} ELSE HKnow)
          /\ \A h \in Hostile \cap CutTo : CutGranted(h) /\ ~HistGranted(h) =>
               \A q \in Accomp : Know(q) \cap Anc(CutOf(h)) = {}
\* m obtains no epoch made knowing its removal (the removal's own included), before its re-add (the
\* re-add's causal past); a new node of m opens a subset (Fresh is within Know)
NoAbsence == RemoveM /\ HasRm =>
  Know(M) \cap ({RmC} \cup Desc(RmC)) \cap (IF CutGranted(M) THEN Anc(CutOf(M)) ELSE EIds) = {}
\* probe: nothing but the cut and what descends from it (fails where a concurrent cut's fork is
\* carried: content written beside the grant, not before it)
StrictNoPast == \A x \in (CutTo \ InitH) : CutGranted(x) /\ ~HistGranted(x) =>
                  Know(x) \subseteq {CutOf(x)} \cup Desc(CutOf(x))

\* settled: nothing an honest party would do is left (hostile parties may do nothing)
Settled == /\ \A v \in Honest : \A i \in Ids \ held[v] : ~Readable(v, i) /\ ~Projectable(v, i)
           /\ ~\E v \in Honest, e \in EIds : AddDue(v, e)
           /\ ~\E v \in Honest, x \in Parties, t \in EIds : TipDue(v, x, t)
           /\ ~\E v \in Admins, x \in Parties, e \in EIds :
                 MayRotate(v) /\ x \in Holders(v) \ {v} /\ e \in Cur(v) \cap Sec(v)
                 /\ ~\E i \in held[v] : <<x, e>> \in C[i].boxes /\ Allowed(v, x, Fl(v, e))
           /\ Cardinality(Cur("a")) <= 1
           /\ ~\E v \in Admins : MayRotate(v) /\ Due(v)

\* honest holders by every commit
Final == ({x \in InitH : ~(x = M /\ HasRm) \/ Granted(x)} \cup {x \in Parties \ InitH : Granted(x)}) \ (Hostile \cup Accomp)
Full == {x \in Final : ~(x \in CutTo /\ CutGranted(x)) \/ HistGranted(x)}

\* settled: a holder with history (prior holders included) opens every epoch from the live state
PriorKeep == Settled => \A x \in Full : EIds \subseteq Fresh(x)
\* settled: a holder without history opens from the live state its cut and all that descends from it
NewReads == Settled => \A x \in Final \ Full : {CutOf(x)} \cup Desc(CutOf(x)) \subseteq Fresh(x)
\* settled: every holder holds every current epoch, established, and all alike
Unlocked == Settled => \A v \in Final : Cur(v) # {} /\ Cur(v) \subseteq Sec(v)
Alike == Settled => \A v, w \in Final : Cur(v) = Cur(w)
\* settled: a re-added m's new node opens every epoch its removal's rotator held
ReaddFresh == Settled /\ RemoveM /\ CutGranted(M) => Anc(RmC) \subseteq Fresh(M)
\* vacuity probe (must fail): no settled state follows every step the bounds allow
NoFullRun == ~(/\ Settled /\ nrot = MaxRot /\ nmerge = MaxMerge /\ nhost = MaxHost
               /\ \A x \in CutTo \cup HistTo : Granted(x) /\ (RemoveM => HasRm))
===============================================================================

------------------------------- MODULE Joint -------------------------------
(* Sealing an actor A to a forked holder actor M (spec/crypto.md §4, Seal). *)
(* M's admins fork M at once, each removing a device the other keeps; A's   *)
(* writers (not in M: they judge M by its keysets alone) forked A sealing  *)
(* M at one fork each, so A's anchors fork. A rotation of A is due. Rule    *)
(* "joint": with no keyset of M past every anchor, A seals M jointly at the *)
(* newest keyset past each (a box opening only for a holder of each);      *)
(* "wait": A's rotation waits for a keyset of M past every anchor (M's      *)
(* merge); "newest": M sealed at its newest keyset, anchors ignored. M's    *)
(* admins may leave for good (Gone); any of them may rotate M (a rotation   *)
(* lists every current keyset it holds), grant a device, or re-seal a       *)
(* member it knows at a current keyset that lacks it. Crypto as access: a   *)
(* device opens a keyset boxed to it or listed by one it opens (history);   *)
(* it reads an epoch of A when it opens every keyset its box to M names,    *)
(* or reads a later epoch of A listing it.                                  *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Dev,      \* M's devices at the start (its admins among them)
          Admins,   \* M's admins: each made one fork of M at the start
          Stays,    \* admins that never leave
          Writers,  \* A's writers, not in M
          New,      \* a device an admin may grant on M (none: "")
          Rule,     \* "joint", "wait" or "newest"
          MaxM,     \* bound on M's keysets
          MaxA      \* bound on A's epochs

VARIABLES ks,     \* M's keysets: [lists, boxed, removes, grants]
          ae,     \* A's epochs: [lists, seal (M's keysets its box to M names)]
          held,   \* held[n]: M's keysets node n holds (admins, writers)
          heldA,  \* heldA[w]: A's epochs writer w holds
          gone,   \* admins gone for good
          granted \* the device granted on M, by whom ({} or {<<admin, device>>})

vars == <<ks, ae, held, heldA, gone, granted>>
Nodes == Admins \cup Writers
KIds == 1..Len(ks)
AIds == 1..Len(ae)
A1 == CHOOSE a \in Admins : TRUE
A2 == CHOOSE a \in Admins : a # A1
\* each fork removes one device the other keeps
X1 == CHOOSE d \in Dev \ Admins : TRUE
X2 == CHOOSE d \in Dev \ Admins : d # X1
W1 == CHOOSE w \in Writers : TRUE
W2 == CHOOSE w \in Writers : w # W1

RECURSIVE Anc(_), AncA(_)
Anc(k) == ks[k].lists \cup UNION {Anc(j) : j \in ks[k].lists}
AncA(e) == ae[e].lists \cup UNION {AncA(f) : f \in ae[e].lists}
Past(k, a) == k = a \/ a \in Anc(k)

Cur(n) == held[n] \ UNION {ks[k].lists : k \in held[n]}
CurA(w) == heldA[w] \ UNION {ae[e].lists : e \in heldA[w]}
Newer(a, b) == Cardinality(Anc(a)) > Cardinality(Anc(b)) \/ (Cardinality(Anc(a)) = Cardinality(Anc(b)) /\ a > b)
NewestOf(s) == CHOOSE k \in s : \A j \in s : j = k \/ Newer(k, j)

\* what an admin knows: removals and grants travel with the keysets it holds
Removed(a) == UNION {ks[k].removes : k \in held[a]}
Grants(a) == UNION {ks[k].grants : k \in held[a]}
Members(a) == ((Dev \cup Grants(a)) \ Removed(a))

\* Seal: the keyset set A's box to M names at writer w ({} : wait)
Anchors(w) == UNION {ae[e].seal : e \in CurA(w)}
Joins(w) == {k \in held[w] : \A a \in Anchors(w) : Past(k, a)}
Seal(w) ==
  IF Rule = "newest" THEN {NewestOf(Cur(w))}
  ELSE IF Joins(w) # {} THEN {NewestOf(Joins(w))}
  ELSE IF Rule = "wait" THEN {}
  ELSE {NewestOf({k \in held[w] : Past(k, a)}) : a \in Anchors(w)}

Init ==
  /\ ks = << [lists |-> {}, boxed |-> Dev, removes |-> {}, grants |-> {}],
             [lists |-> {1}, boxed |-> Dev \ {X1}, removes |-> {X1}, grants |-> {}],
             [lists |-> {1}, boxed |-> Dev \ {X2}, removes |-> {X2}, grants |-> {}] >>
  /\ ae = << [lists |-> {}, seal |-> {1}],
             [lists |-> {1}, seal |-> {2}],
             [lists |-> {1}, seal |-> {3}] >>
  /\ held = [n \in Nodes |-> IF n = A1 \/ n = W1 THEN {1, 2} ELSE IF n = A2 \/ n = W2 THEN {1, 3} ELSE {1}]
  /\ heldA = [w \in Writers |-> IF w = W1 THEN {1, 2} ELSE IF w = W2 THEN {1, 3} ELSE {1}]
  /\ gone = {}
  /\ granted = {}

Deliver(n, k) ==
  /\ k \notin held[n]
  /\ held' = [held EXCEPT ![n] = @ \cup {k}]
  /\ UNCHANGED <<ks, ae, heldA, gone, granted>>

\* an epoch of A arrives with the keysets of M its box names (Carried)
DeliverA(w, e) ==
  /\ e \notin heldA[w]
  /\ heldA' = [heldA EXCEPT ![w] = @ \cup {e}]
  /\ held' = [held EXCEPT ![w] = @ \cup ae[e].seal]
  /\ UNCHANGED <<ks, ae, gone, granted>>

\* the due rotation of A (a departure from A) and later ones, by any writer
RotateA(w) ==
  /\ Len(ae) < MaxA /\ Seal(w) # {}
  /\ ae' = Append(ae, [lists |-> CurA(w), seal |-> Seal(w)])
  /\ heldA' = [heldA EXCEPT ![w] = @ \cup {Len(ae) + 1}]
  /\ UNCHANGED <<ks, held, gone, granted>>
Due == Len(ae) = 3  \* the departure from A: its rotation (any writer's) is owed

\* any admin may rotate M: the rotation lists every current keyset it holds
RotateM(a) ==
  /\ a \notin gone /\ Len(ks) < MaxM
  /\ ks' = Append(ks, [lists |-> Cur(a), boxed |-> Members(a), removes |-> Removed(a), grants |-> Grants(a)])
  /\ held' = [held EXCEPT ![a] = @ \cup {Len(ks) + 1}]
  /\ UNCHANGED <<ae, heldA, gone, granted>>

\* a grant boxes the device at the granter's current keysets; it travels with them
Grant(a) ==
  /\ a \notin gone /\ New # "" /\ granted = {}
  /\ granted' = {<<a, New>>}
  /\ ks' = [k \in KIds |-> IF k \in Cur(a) THEN [ks[k] EXCEPT !.boxed = @ \cup {New}, !.grants = @ \cup {New}] ELSE ks[k]]
  /\ UNCHANGED <<ae, held, heldA, gone>>

\* a re-seal boxes a member the admin knows at a current keyset it holds
Reseal(a) ==
  /\ a \notin gone
  /\ \E k \in Cur(a), d \in Members(a) :
       /\ d \notin ks[k].boxed
       /\ ks' = [ks EXCEPT ![k].boxed = @ \cup {d}]
  /\ UNCHANGED <<ae, held, heldA, gone, granted>>

Gone(a) ==
  /\ a \notin Stays /\ a \notin gone
  /\ gone' = gone \cup {a}
  /\ UNCHANGED <<ks, ae, held, heldA, granted>>

Next ==
  \/ \E n \in Nodes, k \in KIds : Deliver(n, k)
  \/ \E w \in Writers, e \in AIds : DeliverA(w, e)
  \/ \E w \in Writers : RotateA(w)
  \/ \E a \in Admins : RotateM(a) \/ Grant(a) \/ Reseal(a) \/ Gone(a)

\* nothing makes M's admins rotate M (no merge is owed); writers rotate A while it is due
Spec == Init /\ [][Next]_vars
        /\ (\A n \in Nodes, k \in 1..MaxM : WF_vars(k \in KIds /\ Deliver(n, k)))
        /\ (\A w \in Writers, e \in 1..MaxA : WF_vars(e \in AIds /\ DeliverA(w, e)))
        /\ (\A w \in Writers : WF_vars(Due /\ RotateA(w)))
        /\ (\A a \in Admins : WF_vars(Reseal(a)))

\* crypto as access
Opens(d, k) == d \in ks[k].boxed \/ \E j \in KIds : k \in Anc(j) /\ d \in ks[j].boxed
Direct(d, e) == \A k \in ae[e].seal : Opens(d, k)
Reads(d, e) == Direct(d, e) \/ \E f \in AIds : e \in AncA(f) /\ Direct(d, f)

\* a device a keyset of M removes reads no epoch of A sealed (or made after one sealed) past it
NoLeak == \A e \in AIds, k \in KIds : \A d \in ks[k].removes :
            (\E f \in AncA(e) \cup {e} : \E j \in ae[f].seal : Past(j, k)) => ~Reads(d, e)
\* A's due rotation completes with only A's writers online
Rotates == <>~Due
\* every member of M no fork removes reads every epoch of A
Live == {d \in Dev \cup {x[2] : x \in granted} : \A k \in KIds : d \notin ks[k].removes}
ReadsAll == <>[](\A e \in AIds, d \in Live : Reads(d, e))
=============================================================================

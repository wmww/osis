------------------------------ MODULE Account ------------------------------
(* An account's epochs judged at its own nodes against removals from its    *)
(* devices (spec/crypto.md §4 Encrypting under, §9; spec/permissions.md     *)
(* §5.4). The chain is the roster: a removal exists only in the plain       *)
(* rotation carrying it, and a rotation boxes its seed to the roster of the *)
(* line it makes (every node but those a rotation on that line removes).    *)
(* Custody follows holding: a node holds an epoch's seed iff it holds the   *)
(* rotation and is boxed there. Honest nodes remove nodes (`Targets`, each  *)
(* once) or rotate when due (a fork, or a held removal off the head's       *)
(* line), merging every head they hold, rejecting a head whose maker they   *)
(* know removed, from parents whose seeds they hold. Rotations arrive in    *)
(* any order and subsets (each with its line); clocks are HLCs. A writer    *)
(* seals under any held epoch not blocked at it. Rule "order": an epoch is  *)
(* blocked when a known removal is ordered after its rotation; "descent"    *)
(* (the rule): when a known removal is carried by no rotation on the       *)
(* epoch's line whose maker the node does not know removed.                *)
(* A holder actor T (another account's) boxes the account at any epoch     *)
(* made, per keyset (`tks`); a writer seals T at any keyset it holds,      *)
(* holding the account's epoch there or not. `Walk` "stop": a keyset at an *)
(* epoch whose seed the writer lacks is not walked past; "own" (the rule): *)
(* its box to the writer's account is judged: blocked at an epoch the      *)
(* writer holds no rotation of while it knows a removal, or one blocked.   *)
(* `Rogue`: lost node L, once removed, forks at an epoch whose seed it     *)
(* holds, at any clock, boxing anyone. NoLeak: a removed node opens no     *)
(* epoch a node knowing the removal may write under, nor a keyset of T it  *)
(* may seal, unless Rogue L opens it too (what L holds it can hand anyone). *)
(* Settles: a node holding everything and owing no rotation has an epoch   *)
(* to write under, and seals T at any keyset boxing the account at an      *)
(* epoch not blocked at it.                                                *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Honest,   \* the account's honest nodes
          L,        \* the lost node (passive, or Rogue)
          Y,        \* another node, passive
          NoOne,    \* a rotation carrying no removal
          Targets,  \* nodes some honest node may remove (each at most once)
          Rule,     \* "order" or "descent"
          Walk,     \* "stop" or "own": sealing T at a keyset whose seed the writer lacks
          Rogue,    \* L forks after its removal
          MaxRot,   \* bound on rotations
          MaxT,     \* bound on T's keysets
          MaxTs     \* bound on clocks

Nodes == Honest \cup {L, Y}

VARIABLES rots,    \* the rotations: [maker, line, sup, rem, box, ts]; epoch 0 is the first
          hasR,    \* hasR[n]: the rotations honest node n holds
          clk,     \* clk[n]: n's clock
          forged,  \* L's fork made
          tks,     \* tks[j]: the account's epoch T's keyset j boxes it at
          hasT     \* hasT[n]: T's keysets n holds

vars == <<rots, hasR, clk, forged, tks, hasT>>
\* the clocks a commit may take after clock c: under "descent" order is read by nothing,
\* so one value
After(c) == IF Rule = "order" THEN (c + 1)..(MaxTs - 1) ELSE {1}
Ids == 1..Len(rots)
Line(e) == IF e = 0 THEN {} ELSE rots[e].line
Box(e) == IF e = 0 THEN Nodes ELSE rots[e].box
TsOf(e) == IF e = 0 THEN 0 ELSE rots[e].ts
Max(a, b) == IF a > b THEN a ELSE b
Removed == {rots[r].rem : r \in Ids} \ {NoOne}
\* the removals carried by rotations in s
Carried(s) == {rots[r].rem : r \in s} \ {NoOne}
\* the removals n holds (only honest rotations carry one)
Known(n) == Carried(hasR[n])
RmTs(x) == CHOOSE t \in {rots[r].ts : r \in {r \in Ids : rots[r].rem = x}} : TRUE

\* a rotation counts at a node knowing removals `k` while its maker is not among them
Auth(k, r) == rots[r].maker \notin k
CarriedOn(k, s) == Carried({r \in s : Auth(k, r)})
Heads(n) == ({0} \cup hasR[n]) \ UNION {rots[r].sup : r \in hasR[n]}

Blocked(n, e) ==
  \E x \in Known(n) \ {n} :
    IF Rule = "order" THEN TsOf(e) < RmTs(x) ELSE x \notin CarriedOn(Known(n), Line(e))

\* signing::rotations_due: a fork, or a held removal off the head's line
Due(n) == Cardinality(Heads(n)) > 1 \/
  \E h \in Heads(n) : (Known(n) \ {n}) \ CarriedOn(Known(n), Line(h)) # {}

Live(n) == n \in Honest /\ n \notin Removed

\* custody follows holding: n holds e's seed where it holds e boxed to it
Seeded(n, e) == e = 0 \/ (e \in hasR[n] /\ n \in Box(e))

\* sealing T at keyset j is blocked at n: through T's box to the account at e
BlockedT(n, j) ==
  LET e == tks[j]
  IN IF Walk = "own" THEN IF e \in {0} \cup hasR[n] THEN Blocked(n, e) ELSE Known(n) \ {n} # {}
     ELSE Seeded(n, e) /\ Blocked(n, e)

Init ==
  /\ rots = <<>>
  /\ hasR = [n \in Honest |-> {}]
  /\ clk = [n \in Honest |-> 0]
  /\ forged = FALSE
  /\ tks = <<>>
  /\ hasT = [n \in Honest |-> {}]

\* n's rotation removing x (x = n: none, a merge or a due rotation)
Rotate(n, x) ==
  /\ Live(n)
  /\ Len(rots) < MaxRot
  /\ IF x = n THEN Due(n) ELSE x \in Targets /\ x \notin Removed
  /\ \E t \in After(clk[n]) :
       LET rem == IF x = n THEN NoOne ELSE x
           k == Known(n) \cup ({rem} \ {NoOne})
           hs == Heads(n)
           parents == {h \in hs : h = 0 \/ Auth(k, h)}
           pl == UNION {Line(p) : p \in parents}
           id == Len(rots) + 1
       IN /\ parents # {}
          /\ \A q \in parents : Seeded(n, q)
          /\ rots' = Append(rots, [maker |-> n, line |-> pl \cup {id}, sup |-> hs, rem |-> rem,
                                   box |-> Nodes \ (Carried(pl) \cup ({rem} \ {NoOne})), ts |-> t + 1])
          /\ hasR' = [hasR EXCEPT ![n] = @ \cup {id}]
          /\ clk' = [clk EXCEPT ![n] = t + 1]
  /\ UNCHANGED <<forged, tks, hasT>>

\* L, removed, forks at an epoch whose seed it holds
Forge ==
  /\ Rogue /\ ~forged /\ L \in Removed /\ Len(rots) < MaxRot
  /\ \E p \in {0} \cup {r \in Ids : L \in Box(r)}, t \in After(0) :
       LET id == Len(rots) + 1
       IN rots' = Append(rots, [maker |-> L, line |-> Line(p) \cup {id}, sup |-> {p}, rem |-> NoOne,
                                box |-> Nodes, ts |-> t])
  /\ forged' = TRUE
  /\ UNCHANGED <<hasR, clk, tks, hasT>>

GetRot(n, r) ==
  /\ n \in Honest /\ r \notin hasR[n] /\ Line(r) \ {r} \subseteq hasR[n]
  /\ hasR' = [hasR EXCEPT ![n] = @ \cup {r}]
  /\ clk' = [clk EXCEPT ![n] = Max(@, rots[r].ts)]
  /\ UNCHANGED <<rots, forged, tks, hasT>>

\* T's admin, outside the account, boxes it at any epoch made
TKey ==
  /\ Len(tks) < MaxT
  /\ \E e \in {0} \cup Ids : tks' = Append(tks, e)
  /\ UNCHANGED <<rots, hasR, clk, forged, hasT>>

GetT(n, j) ==
  /\ n \in Honest /\ j \notin hasT[n]
  /\ hasT' = [hasT EXCEPT ![n] = @ \cup {j}]
  /\ UNCHANGED <<rots, hasR, clk, forged, tks>>

Next ==
  \/ \E n \in Honest : \E x \in Targets \cup {n} : Rotate(n, x)
  \/ Forge
  \/ \E n \in Honest, r \in Ids : GetRot(n, r)
  \/ TKey
  \/ \E n \in Honest, j \in 1..Len(tks) : GetT(n, j)

Spec == Init /\ [][Next]_vars

\* what a live node may write under (knowledge only grows, so a state invariant is every write),
\* unless hostile L opens it: what L holds it can hand any party (Cover.tla's excuse)
NoLeak == \A n \in Honest : Live(n) =>
  /\ \A e \in {0} \cup hasR[n] : ~Blocked(n, e) /\ ~(Rogue /\ L \in Box(e)) => \A x \in Known(n) \ {n} : x \notin Box(e)
  /\ \A j \in hasT[n] : ~BlockedT(n, j) /\ ~(Rogue /\ L \in Box(tks[j])) => \A x \in Known(n) \ {n} : x \notin Box(tks[j])

\* a live node holding everything, owing no rotation, has an epoch to write under
Settles == \A n \in Honest :
  (Live(n) /\ hasR[n] = Ids /\ ~Due(n))
    => /\ \E e \in {0} \cup hasR[n] : ~Blocked(n, e)
       /\ \A j \in hasT[n] : ~Blocked(n, tks[j]) => ~BlockedT(n, j)
=============================================================================

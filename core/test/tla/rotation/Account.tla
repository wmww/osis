------------------------------ MODULE Account ------------------------------
(* An account's epochs judged at its own nodes against removals from its    *)
(* devices actor D (spec/crypto.md §4 Encrypting under, §9; spec/           *)
(* permissions.md §3, §5.5). Honest nodes remove nodes from D: the removal  *)
(* with D's rotation, then the account's rotation, whose seed goes into D's *)
(* `account.0` under D's epoch the removal mints, so it opens for the nodes *)
(* the remover's roster still holds (Box), and whose thing list names the   *)
(* removals held at the epochs it closes that no rotation already names     *)
(* (by the cutoff: an authorized rotation on its line). A rotation merges   *)
(* every head its maker holds, rejecting (superseding unnamed) a head whose *)
(* maker the node knows removed. Commits arrive in any order and subsets    *)
(* (a rotation with its chain); clocks are HLCs, so concurrent commits take *)
(* any order. A writer seals content under any held epoch not blocked at it *)
(* (another account's admin boxed the account at any of its epochs).       *)
(* Rule "order": an epoch is blocked when a known removal is ordered after  *)
(* its rotation (the first epoch: after creation). Rule "descent": when a   *)
(* known removal is named by no rotation on the epoch's line whose maker    *)
(* the node does not know removed. `Met`: a node rotates only holding      *)
(* every removal the maker of each rotation on the line it extends held    *)
(* (`know`: the names of D's epoch that rotation's seed sits under, met    *)
(* where that epoch is established; without it a D epoch whose names a     *)
(* node has not met still opens the seed for reading).                     *)
(* `Rogue`: lost node L, once removed, rotates at an epoch whose seed it    *)
(* holds, naming any removals made, at any clock, boxing anyone. NoLeak: a  *)
(* removed node opens no content written by a node that knew of the        *)
(* removal, unless Rogue L opens it too (what L holds it can hand anyone).  *)
(* Settles: a node holding everything and owing no rotation has an epoch   *)
(* to write under.                                                          *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Honest,   \* the account's honest nodes
          L,        \* the lost node (passive, or Rogue)
          Y,        \* another node, passive
          Targets,  \* nodes some honest node may remove (each at most once)
          Rule,     \* "order" or "descent"
          Met,      \* a rotation needs the removals named on its line held
          Rogue,    \* L forks after its removal
          AnyLine,  \* a removal named on any held line owes no rotation
          MaxRot,   \* bound on rotations
          MaxTs     \* bound on clocks

Nodes == Honest \cup {L, Y}

VARIABLES rots,    \* the rotations: [maker, line, sup, names, box, know, ts]; epoch 0 is the first
          rm,      \* rm[x]: the clock of x's removal from D (0: not removed)
          hasR,    \* hasR[n]: the rotations honest node n holds
          hasX,    \* hasX[n]: the removals n holds
          clk,     \* clk[n]: n's clock
          forged   \* L's fork made

vars == <<rots, rm, hasR, hasX, clk, forged>>
\* the clocks a commit may take after clock c: under "descent" order is read by nothing,
\* so one value (a removal's 1 marks it made)
After(c) == IF Rule = "order" THEN (c + 1)..(MaxTs - 1) ELSE {1}
Ids == 1..Len(rots)
Line(e) == IF e = 0 THEN {} ELSE rots[e].line
Box(e) == IF e = 0 THEN Nodes ELSE rots[e].box
TsOf(e) == IF e = 0 THEN 0 ELSE rots[e].ts
Max(a, b) == IF a > b THEN a ELSE b

\* a rotation counts at a node knowing removals `k` while its maker is not among them
Auth(k, r) == rots[r].maker \notin k
NamedOn(k, s) == {x \in Targets : \E r \in s : x \in rots[r].names /\ Auth(k, r)}
Heads(n) == ({0} \cup hasR[n]) \ UNION {rots[r].sup : r \in hasR[n]}

Blocked(n, e) ==
  \E x \in hasX[n] \ {n} :
    IF Rule = "order" THEN TsOf(e) < rm[x] ELSE x \notin NamedOn(hasX[n], Line(e))

\* signing::rotations_due: a fork, or a held removal no rotation on the head's line names
\* (`AnyLine`: none anywhere names, a negative control)
Due(n) == Cardinality(Heads(n)) > 1 \/
  \E h \in Heads(n) : (hasX[n] \ {n}) \ NamedOn(hasX[n], IF AnyLine THEN hasR[n] ELSE Line(h)) # {}

Live(n) == n \in Honest /\ (n \in Targets => rm[n] = 0)

Init ==
  /\ rots = <<>>
  /\ rm = [x \in Targets |-> 0]
  /\ hasR = [n \in Honest |-> {}]
  /\ hasX = [n \in Honest |-> {}]
  /\ clk = [n \in Honest |-> 0]
  /\ forged = FALSE

\* n's rotation, after removing x (x = n: none, a merge or a due naming)
Rotate(n, x) ==
  /\ Live(n)
  /\ Len(rots) < MaxRot
  /\ IF x = n THEN Due(n) ELSE x \in Targets /\ rm[x] = 0
  /\ \E t \in After(clk[n]) :
       LET k == IF x = n THEN hasX[n] ELSE hasX[n] \cup {x}
           hs == Heads(n)
           parents == {h \in hs : h = 0 \/ Auth(k, h)}
           pl == UNION {Line(p) : p \in parents}
           id == Len(rots) + 1
       IN /\ parents # {}
          /\ Met => \A q \in pl : rots[q].know \subseteq k
          /\ rots' = Append(rots, [maker |-> n, line |-> pl \cup {id}, sup |-> hs,
                                   names |-> (k \ {n}) \ NamedOn(k, pl), box |-> Nodes \ k, know |-> k, ts |-> t + 1])
          /\ rm' = IF x = n THEN rm ELSE [rm EXCEPT ![x] = t]
          /\ hasR' = [hasR EXCEPT ![n] = @ \cup {id}]
          /\ hasX' = [hasX EXCEPT ![n] = k]
          /\ clk' = [clk EXCEPT ![n] = t + 1]
  /\ UNCHANGED forged

\* L, removed, forks at an epoch whose seed it holds
Forge ==
  /\ Rogue /\ ~forged /\ L \in Targets /\ rm[L] > 0 /\ Len(rots) < MaxRot
  /\ \E p \in {0} \cup {r \in Ids : L \in Box(r)}, nm \in SUBSET {x \in Targets : rm[x] > 0}, t \in After(0) :
       LET id == Len(rots) + 1
       IN rots' = Append(rots, [maker |-> L, line |-> Line(p) \cup {id}, sup |-> {p},
                                names |-> nm, box |-> Nodes, know |-> {}, ts |-> t])
  /\ forged' = TRUE
  /\ UNCHANGED <<rm, hasR, hasX, clk>>

GetRot(n, r) ==
  /\ n \in Honest /\ r \notin hasR[n] /\ Line(r) \ {r} \subseteq hasR[n]
  /\ hasR' = [hasR EXCEPT ![n] = @ \cup {r}]
  /\ clk' = [clk EXCEPT ![n] = Max(@, rots[r].ts)]
  /\ UNCHANGED <<rots, rm, hasX, forged>>

GetRm(n, x) ==
  /\ n \in Honest /\ rm[x] > 0 /\ x \notin hasX[n]
  /\ hasX' = [hasX EXCEPT ![n] = @ \cup {x}]
  /\ clk' = [clk EXCEPT ![n] = Max(@, rm[x])]
  /\ UNCHANGED <<rots, rm, hasR, forged>>

Next ==
  \/ \E n \in Honest : \E x \in Targets \cup {n} : Rotate(n, x)
  \/ Forge
  \/ \E n \in Honest, r \in Ids : GetRot(n, r)
  \/ \E n \in Honest, x \in Targets : GetRm(n, x)

Spec == Init /\ [][Next]_vars

\* what a live node may write under (knowledge only grows, so a state invariant is every write),
\* unless hostile L opens it: what L holds it can hand any party (Cover.tla's excuse)
NoLeak == \A n \in Honest : Live(n) =>
  \A e \in {0} \cup hasR[n] : ~Blocked(n, e) /\ ~(Rogue /\ L \in Box(e)) => \A x \in hasX[n] \ {n} : x \notin Box(e)

\* a live node holding everything, owing no rotation, has an epoch to write under
Settles == \A n \in Honest :
  (Live(n) /\ hasR[n] = Ids /\ hasX[n] = {x \in Targets : rm[x] > 0} /\ ~Due(n))
    => \E e \in {0} \cup hasR[n] : ~Blocked(n, e)
=============================================================================

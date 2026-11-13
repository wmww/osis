------------------------------ MODULE JointRule ------------------------------
(* When is a joint box to holder actor M blocked (spec/crypto.md §4, Seal)? *)
(* Static: every small configuration at once (Init), no steps. M forked    *)
(* into two keysets; M's direct holders are device x and holder actors N,  *)
(* P (members among devices x, q). A node knows departures from M (any of  *)
(* x, N, P) and from N and P (their members). Each fork of M either covers *)
(* a removal from M (made knowing it: no box to the removed holder) or     *)
(* misses it (boxes it), and boxes N, P at their old keyset (every member) *)
(* or at their new one (covering every removal from them). A fork misses   *)
(* each departure edge it so leaves open: what the build's Blocked finds   *)
(* (directly, or by the box clause through N, P). Rule decides when the    *)
(* joint box naming both forks is blocked:                                 *)
(*   "any":   some fork misses some departure (the build);                 *)
(*   "edge":  one departure edge every fork misses;                        *)
(*   "party": one departed party (the removed holder) every fork misses;   *)
(*   "every": every fork misses some departure.                            *)
EXTENDS FiniteSets

CONSTANT Rule

Devs == {"x", "q"}
Acts == {"N", "P"}
Direct == {"x"} \cup Acts
Forks == {1, 2}

VARIABLES rmM,    \* direct holders removed from M (known)
          mem,    \* mem[h]: h's members (devices)
          rmA,    \* rmA[h]: members removed from h (known)
          covM,   \* covM[f]: removals from M fork f covers
          atNew   \* atNew[f][h]: fork f boxes h at its keyset covering rmA[h]
vars == <<rmM, mem, rmA, covM, atNew>>

Init ==
  /\ rmM \in SUBSET Direct
  /\ mem \in [Acts -> SUBSET Devs]
  /\ rmA \in {r \in [Acts -> SUBSET Devs] : \A h \in Acts : r[h] \subseteq mem[h]}
  /\ covM \in [Forks -> SUBSET rmM]
  /\ atNew \in [Forks -> [Acts -> BOOLEAN]]
Spec == Init /\ [][UNCHANGED vars]_vars

Boxes(f) == Direct \ covM[f]
Members(f, h) == IF atNew[f][h] THEN mem[h] \ rmA[h] ELSE mem[h]
Opens(d, f) == d \in Boxes(f) \/ \E h \in Acts \cap Boxes(f) : d \in Members(f, h)
\* a device still reaching M by some standing path
Legit == ({"x"} \ rmM) \cup UNION {mem[h] \ rmA[h] : h \in Acts \ rmM}
Departed == Devs \ Legit

\* departure edges fork f misses: <<party, actor it left>>
Miss(f) == {<<h, "M">> : h \in rmM \cap Boxes(f)}
           \cup UNION {{<<d, h>> : d \in rmA[h] \cap Members(f, h)} : h \in Acts \cap Boxes(f)}
Party(f) == {e[1] : e \in Miss(f)}

Blocked ==
  CASE Rule = "any"   -> \E f \in Forks : Miss(f) # {}
    [] Rule = "edge"  -> \E e \in Miss(1) : e \in Miss(2)
    [] Rule = "party" -> \E p \in Party(1) : p \in Party(2)
    [] Rule = "every" -> \A f \in Forks : Miss(f) # {}

\* a departed device opens the joint box
NoLeak == ~Blocked => ~\E d \in Departed : \A f \in Forks : Opens(d, f)
\* departed devices pooling what they hold open it (spec/requirements.md: rights held by
\* different parties never combine into a right neither has alone)
NoPooledLeak == ~Blocked => ~\A f \in Forks : \E d \in Departed : Opens(d, f)
\* a fork covering every departure the node knows is enough to seal M (the issue)
Seals == (\E f \in Forks : Miss(f) = {}) => ~Blocked
=============================================================================

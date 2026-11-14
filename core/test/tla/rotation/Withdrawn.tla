------------------------------ MODULE Withdrawn ------------------------------
(* Whether any rule passes on a withdrawn epoch's secret both safely and      *)
(* live (spec/crypto.md §4 Unsuperseded and withdraw; notes/crypto.md).    *)
(* A demotes admin a2 (D); a2, unaware, removes M                            *)
(* (W); R, holding W alone, rotates read (Rot: e_R, naming W, boxing A, a2,   *)
(* R, a3 and not M) and writes under it (a2 judges as A, M and N decide     *)
(* nothing, so they are left out). R also grants N read (NG) later.    *)
(* Worlds: "none"; "G": a3, holding D, re-granted a2 between D and W, so W    *)
(* applies again; "X": a4 demoted A before D, voiding D, so W applies. a3 and *)
(* a4 may stay offline for good (their sends have no fairness), as may any    *)
(* re-grant RG of M by A after W. A node passes e_R on (to M, to N) by Rule:  *)
(*   "met"      e_R established (names met: W applies): the build;          *)
(*   "refuted"  also where W is held and applies nothing (option B);         *)
(*   "regrant"  also where refuted and A's re-grant of M after W is held;    *)
(*   "wait"     also where refuted and a3 attested what it held (Ack3);      *)
(*   "waitall"  ... and a4 too (Ack4);                                      *)
(*   "joiners"  "met" for M; for N also where refuted (excluding by names). *)
(* NoLeakM: M is never handed e_R where W applies in the world's commits and *)
(* no valid re-grant follows it, but by a node holding a re-grant it judges   *)
(* valid (an admin's grant concurrent with its own unseen demotion: a stated *)
(* limit, spec/crypto.md §4 Boxes). LiveM: in world "none" (M a reader all    *)
(* along) M gets e_R. LiveN: N, granted after, gets e_R.                     *)
EXTENDS FiniteSets

CONSTANTS Rule

Nodes == {"A", "R", "a3", "a4"}        \* the nodes whose holdings matter
Offline == {"a3", "a4"}
Boxed == {"A", "R"}                    \* e_R's holders that judge (a2 judges as A; a3
                                       \* hands M nothing: it holds G or X is not its)
Cs == {"D", "W", "Rot", "G", "X", "RG", "NG", "Ack3", "Ack4"}

VARIABLES world, held, mHas, nHas, leakM, leakN
vars == <<world, held, mHas, nHas, leakM, leakN>>

All == UNION {held[n] : n \in Nodes}

\* judged over a set of commits h
Dv(h) == "D" \in h /\ "X" \notin h
A2Adm(h) == ~Dv(h) \/ "G" \in h
Wap(h) == "W" \in h /\ A2Adm(h)
RGv(h) == "RG" \in h /\ "X" \notin h
MMem(h) == ~Wap(h) \/ RGv(h)
NMem(h) == "NG" \in h
Est(h) == "Rot" \in h /\ Wap(h)
Refuted(h) == "Rot" \in h /\ "W" \in h /\ ~Wap(h)

UsableM(h) ==
  \/ Est(h)
  \/ /\ Refuted(h)
     /\ \/ Rule = "refuted"
        \/ Rule = "regrant" /\ RGv(h)
        \/ Rule = "wait" /\ "Ack3" \in h
        \/ Rule = "waitall" /\ "Ack3" \in h /\ "Ack4" \in h
UsableN(h) == UsableM(h) \/ (Rule = "joiners" /\ Refuted(h))

Init ==
  /\ world \in {"none", "G", "X"}
  /\ held = [n \in Nodes |->
       CASE n = "A" -> {"D"}
         [] n = "R" -> {"W", "Rot", "NG"}
         [] n = "a3" -> {"D"} \cup (IF world = "G" THEN {"G"} ELSE {})
         [] n = "a4" -> IF world = "X" THEN {"X"} ELSE {}]
  /\ mHas = FALSE /\ nHas = FALSE /\ leakM = FALSE /\ leakN = FALSE

\* an attestation carries what its author holds
Bundle(c) == IF c = "Ack3" THEN {c} \cup (held["a3"] \cap {"G"})
             ELSE IF c = "Ack4" THEN {c} \cup (held["a4"] \cap {"X"}) ELSE {c}

Get(d, c) ==
  /\ c \notin held[d]
  /\ held' = [held EXCEPT ![d] = @ \cup Bundle(c)]
  /\ UNCHANGED <<world, mHas, nHas, leakM, leakN>>
\* what each node needs (NG stays at R, which grants N)
Needs(d) == IF d \in Boxed THEN Cs \ {"NG"} ELSE {"W", "Rot"}
\* W reaches A as a2's commit; the rest from a node holding it
DeliverOn(d, c) == c \in Needs(d) /\ (c \in UNION {held[s] : s \in Nodes \ Offline} \/ c = "W") /\ Get(d, c)
DeliverOff(d, c) == c \in Needs(d) /\ c \in UNION {held[s] : s \in Offline} /\ Get(d, c)

WriteRG ==
  /\ "W" \in held["A"] /\ "RG" \notin held["A"]
  /\ held' = [held EXCEPT !["A"] = @ \cup {"RG"}]
  /\ UNCHANGED <<world, mHas, nHas, leakM, leakN>>

Attest(n, c) ==
  /\ {"W", "Rot"} \subseteq held[n] /\ c \notin held[n]
  /\ held' = [held EXCEPT ![n] = @ \cup {c}]
  /\ UNCHANGED <<world, mHas, nHas, leakM, leakN>>

HandM(n) ==
  /\ n \in Boxed /\ "Rot" \in held[n] /\ ~mHas
  /\ UsableM(held[n]) /\ MMem(held[n])
  /\ mHas' = TRUE /\ leakM' = (leakM \/ (~MMem(All) /\ ~RGv(held[n])))
  /\ UNCHANGED <<world, held, nHas, leakN>>

HandN(n) ==
  /\ n \in Boxed /\ "Rot" \in held[n] /\ ~nHas
  /\ UsableN(held[n]) /\ NMem(held[n])
  /\ nHas' = TRUE /\ leakN' = (leakN \/ ~NMem(All))
  /\ UNCHANGED <<world, held, mHas, leakM>>

Next ==
  \/ \E d \in Nodes, c \in Cs : DeliverOn(d, c) \/ DeliverOff(d, c)
  \/ WriteRG
  \/ Rule \in {"wait", "waitall"} /\ (Attest("a3", "Ack3") \/ Attest("a4", "Ack4"))
  \/ \E n \in Boxed : HandM(n) \/ HandN(n)

Fair ==
  /\ \A d \in Nodes, c \in Cs : WF_vars(DeliverOn(d, c))
  /\ \A n \in Boxed : WF_vars(HandM(n)) /\ WF_vars(HandN(n))

Spec == Init /\ [][Next]_vars /\ Fair

NoLeakM == ~leakM
NoLeakN == ~leakN
LiveM == (world = "none") => <>mHas
LiveN == <>nHas
=============================================================================

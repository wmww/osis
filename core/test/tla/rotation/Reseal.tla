------------------------------ MODULE Reseal ------------------------------
(* Under which epoch a node may encrypt again content another wrote        *)
(* (spec/crypto.md §5 Section; issues/reseal-under-own-epoch-leaks.md).     *)
(* a2 removes reader M (W). R, holding W, rotates read (Rot: e_R, naming W, *)
(* boxing V and not M) and writes w under e_R. V holds e_R's secret by its  *)
(* box; its own current epoch before e_R is e_V, which M holds. A host may  *)
(* withhold W from V for good (no fairness for W to V). Worlds, as in       *)
(* Withdrawn.tla: "plain" (W applies everywhere); "none" (A demoted a2 (D)  *)
(* before W, voiding it: M a reader all along); "G" (as none, but a3, maybe *)
(* offline for good, re-granted a2 between D and W, so W applies); "X" (a4, *)
(* maybe offline, demoted A before D, voiding D). A, online, holds D in   *)
(* every world but plain, and may hand it to V at any time.                *)
(* M, holding e_V, forges sections of w's commit under e_V (garbage parts). *)
(* V opens every section it holds a secret for and records the epoch of    *)
(* each opening it takes as w's (Genuine: only one whose parts verify).    *)
(* V then encrypts w again: a fresh encryption (Reseal) by ResealRule, or a *)
(* snapshot folding w, under an epoch of its own choosing, by SnapRule:     *)
(*   "newest"    its newest current epoch (the bug);                       *)
(*   "opened"    an epoch it recorded w opened under (never its choice);    *)
(*   "openedest" ... established here now;                                 *)
(*   "chosen"    its newest current epoch while an epoch w opened under is *)
(*               established here now (the build, both);                   *)
(*   "atopen"    ... established when it opened (negative control);        *)
(*   "never"     no fresh encryption of another's content (a snapshot      *)
(*               cannot copy a section verbatim).                           *)
(* NoLeak: M never holds a ciphertext of w while W applies in the world's   *)
(* commits. Live (world plain, W delivered): V encrypts w again.           *)
EXTENDS FiniteSets

CONSTANTS ResealRule, SnapRule, Genuine, Worlds

Nodes == {"V", "A", "a3", "a4"}
Cs == {"D", "W", "Rot", "G", "X"}

VARIABLES world, held, cts, opened, again
vars == <<world, held, cts, opened, again>>

All == UNION {held[n] : n \in Nodes} \cup {"W", "Rot"}

Dv(h) == "D" \in h /\ "X" \notin h
A2Adm(h) == ~Dv(h) \/ "G" \in h
Wap(h) == "W" \in h /\ A2Adm(h)
\* e_R established: its rotation held and its names (W) met
Est(h, e) == e = "eV" \/ ("Rot" \in h /\ Wap(h))
\* V's newest current epoch: e_R once established (it supersedes e_V)
Newest(h) == IF Est(h, "eR") THEN "eR" ELSE "eV"
MRemoved == Wap(All)
\* epochs M holds
MHolds == {"eV"}

Init ==
  /\ world \in Worlds
  /\ held = [n \in Nodes |->
       CASE n = "V" -> {"Rot"}
         [] n = "A" -> IF world = "plain" THEN {} ELSE {"D"}
         [] n = "a3" -> IF world = "G" THEN {"D", "G"} ELSE {}
         [] n = "a4" -> IF world = "X" THEN {"X"} ELSE {}]
  \* a ciphertext: content ("w" or M's forgery "junk") and the epoch it is under
  /\ cts = {[c |-> "w", e |-> "eR"]}
  \* V's record of w's openings: epoch, and whether it was established then
  /\ opened = {}
  /\ again = FALSE

Deliver(c) ==
  /\ c \in Cs /\ c \notin held["V"]
  /\ c = "W" \/ c \in UNION {held[s] : s \in Nodes \ {"V"}}
  /\ held' = [held EXCEPT !["V"] = @ \cup {c}]
  /\ UNCHANGED <<world, cts, opened, again>>

Forge ==
  /\ [c |-> "junk", e |-> "eV"] \notin cts
  /\ cts' = cts \cup {[c |-> "junk", e |-> "eV"]}
  /\ UNCHANGED <<world, held, opened, again>>

Open(ct) ==
  /\ ct \in cts
  /\ ct.c = "w" \/ ~Genuine
  /\ [e |-> ct.e, est |-> Est(held["V"], ct.e)] \notin opened
  /\ opened' = opened \cup {[e |-> ct.e, est |-> Est(held["V"], ct.e)]}
  /\ UNCHANGED <<world, held, cts, again>>

\* the epochs V may put w under by rule r
Under(r) ==
  LET h == held["V"]
      es == {o.e : o \in opened}
  IN CASE r = "newest" -> IF es # {} THEN {Newest(h)} ELSE {}
       [] r = "opened" -> es
       [] r = "openedest" -> {e \in es : Est(h, e)}
       [] r = "chosen" -> IF \E e \in es : Est(h, e) THEN {Newest(h)} ELSE {}
       [] r = "atopen" -> IF \E o \in opened : o.est THEN {Newest(h)} ELSE {}
       [] r = "never" -> {}

Encrypt(r) ==
  \E e \in Under(r) :
    /\ ~again \/ [c |-> "w", e |-> e] \notin cts
    /\ cts' = cts \cup {[c |-> "w", e |-> e]}
    /\ again' = TRUE
    /\ UNCHANGED <<world, held, opened>>

Next ==
  \/ \E c \in Cs : Deliver(c)
  \/ Forge
  \/ \E ct \in cts : Open(ct)
  \/ Encrypt(ResealRule)
  \/ Encrypt(SnapRule)

Fair ==
  /\ WF_vars(Deliver("W")) /\ WF_vars(Deliver("Rot"))
  /\ \A ct \in [c : {"w"}, e : {"eV", "eR"}] : WF_vars(Open(ct))
  /\ WF_vars(Encrypt(ResealRule)) /\ WF_vars(Encrypt(SnapRule))

Spec == Init /\ [][Next]_vars /\ Fair

NoLeak == MRemoved => ~\E ct \in cts : ct.c = "w" /\ ct.e \in MHolds
Live == (world = "plain") => <>again
=============================================================================

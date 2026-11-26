------------------------------- MODULE KemKeys -------------------------------
(* KEM keys published only where something seals to them (spec/crypto.md §3  *)
(* Published KEM keys), Seal's candidates (§4 Holder actors, Seal) and the    *)
(* granter's check (spec/permissions.md §2 Granting to a thing). Holder actor *)
(* M of thing A, read role, M's keysets a line (no forks). m, an admin of M,  *)
(* rotates M; it learns M's grant on A only from a signal or a stub of A it *)
(* holds (Learn: fair where Told, else it may never). g, a writer of A that *)
(* may not rotate M, grants M                                                *)
(* read on A and seals M at each rotation or re-seal of A, by the newest     *)
(* keyset of M it holds (from a card or M's readers' reports: Report).       *)
(* x is a party removed from M (RemoveX, a rotation knowing it), or the      *)
(* public granted read on M and removed: an open box hands every party M's   *)
(* secret at each keyset made while it holds, so x is every party.           *)
(* `other`: some other reason M's keyset carries a KEM key when written (a   *)
(* card of M standing, a role elsewhere, a signal enabled), which may end.   *)
(* Rule:                                                                     *)
(*   "written"  a keyset's KEM key decided when written, nothing more;      *)
(*   "due"      also: a node that may rotate M rotates it while M's current *)
(*              keyset lacks a KEM key the rule gives by what it holds now; *)
(*   "sticky"   "due", and a keyset carries a KEM key wherever the keyset   *)
(*              it supersedes does: no node need know of a grant;           *)
(*   "fallback" "due", but Seal takes the newest keyset carrying a KEM key  *)
(*              below a KEM-less newest one (control: a stale box).          *)
(* Check: g grants only where the newest keyset of M it holds carries a KEM *)
(* key (it may not rotate M). StaleCard: g starts holding a card one keyset *)
(* behind, x already removed.                                                *)
(* Invariants: NoLeak (content g seals once it holds a keyset made knowing  *)
(* x's removal is never sealed to a keyset x holds); NoLeakAll (no content  *)
(* x opens after its removal at all: the stated limit of a stale view,     *)
(* spec/crypto.md §4 Holder actors). Property Live: once granted, M is      *)
(* boxed at its newest keyset for good.                                      *)
EXTENDS Naturals, Sequences

CONSTANTS Rule, Check, StaleCard, Other0, MaxM, Told

VARIABLES ks, other, mGrant, xRemoved, gk, granted, box, rotsM, leak, leakAll
vars == <<ks, other, mGrant, xRemoved, gk, granted, box, rotsM, leak, leakAll>>

K(kem, x) == [kem |-> kem, x |-> x]
Newest == Len(ks)
\* m's KEM rule by what it holds now: M holds a role on A (it learned
\* the grant), or another reason stands
KemNow == other \/ mGrant

\* the keyset g seals M at: its newest held one where that carries a KEM key,
\* else none (left out: an older one is stale, blocked by a box); "fallback"
\* takes the newest older one carrying a KEM key
Older(j) == {i \in 1..j : ks[i].kem}
Target ==
  IF ks[gk].kem THEN gk
  ELSE IF Rule = "fallback" /\ Older(gk) # {}
       THEN CHOOSE i \in Older(gk) : \A j \in Older(gk) : j <= i
       ELSE 0
\* g holds a keyset made knowing x's removal
Knows == \E i \in 1..gk : ~ks[i].x
\* content sealed at keyset t: x opens it
Opens(t) == t # 0 /\ ks[t].x

Init ==
  /\ IF StaleCard
       THEN ks = <<K(TRUE, TRUE), K(TRUE, FALSE)>> /\ xRemoved = TRUE /\ gk = 1
       ELSE ks = <<K(Other0, TRUE)>> /\ xRemoved = FALSE /\ gk = 1
  /\ other = (Other0 \/ StaleCard)
  /\ mGrant = FALSE /\ granted = FALSE /\ box = 0 /\ rotsM = 0
  /\ leak = FALSE /\ leakAll = FALSE

\* g seals M at Target and writes content under that epoch of A
SealAt(t) ==
  /\ box' = t
  /\ leak' = (leak \/ (Opens(t) /\ Knows))
  /\ leakAll' = (leakAll \/ (Opens(t) /\ xRemoved))

Grant ==
  /\ ~granted
  /\ ~Check \/ ks[gk].kem
  /\ granted' = TRUE
  /\ SealAt(Target)
  /\ UNCHANGED <<ks, other, mGrant, xRemoved, gk, rotsM>>

\* a rotation or re-seal of A: due once g's view moved
Seal ==
  /\ granted /\ box # Target
  /\ SealAt(Target)
  /\ UNCHANGED <<ks, other, mGrant, xRemoved, gk, granted, rotsM>>

Learn ==
  /\ granted /\ ~mGrant
  /\ mGrant' = TRUE
  /\ UNCHANGED <<ks, other, xRemoved, gk, granted, box, rotsM, leak, leakAll>>

Report ==
  /\ gk < Newest
  /\ gk' = Newest
  /\ UNCHANGED <<ks, other, mGrant, xRemoved, granted, box, rotsM, leak, leakAll>>

EndOther ==
  /\ other
  /\ other' = FALSE
  /\ UNCHANGED <<ks, mGrant, xRemoved, gk, granted, box, rotsM, leak, leakAll>>

\* the KEM key a keyset m writes now carries
KemW == KemNow \/ (Rule = "sticky" /\ ks[Newest].kem)

RotM ==
  /\ rotsM < MaxM
  /\ ks' = Append(ks, K(KemW, ~xRemoved))
  /\ rotsM' = rotsM + 1
  /\ UNCHANGED <<other, mGrant, xRemoved, gk, granted, box, leak, leakAll>>

RemoveX ==
  /\ ~xRemoved
  /\ xRemoved' = TRUE
  /\ ks' = Append(ks, K(KemW, FALSE))
  /\ UNCHANGED <<other, mGrant, gk, granted, box, rotsM, leak, leakAll>>

DueM ==
  /\ Rule \in {"due", "sticky", "fallback"}
  /\ KemNow /\ ~ks[Newest].kem
  /\ ks' = Append(ks, K(TRUE, ~xRemoved))
  /\ UNCHANGED <<other, mGrant, xRemoved, gk, granted, box, rotsM, leak, leakAll>>

Next == Grant \/ Seal \/ Learn \/ Report \/ EndOther \/ RotM \/ RemoveX \/ DueM

Fair == WF_vars(Grant) /\ WF_vars(Seal) /\ (Told => WF_vars(Learn)) /\ WF_vars(Report) /\ WF_vars(DueM)

Spec == Init /\ [][Next]_vars /\ Fair

NoLeak == ~leak
NoLeakAll == ~leakAll
Live == <>[](granted => box = Newest)
=============================================================================

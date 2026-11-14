------------------------------- MODULE Planted -------------------------------
(* What a `secrets.0` compaction snapshot carries when the state keys an
   epoch no valid rotation made (spec/crypto.md §4 Established; notes/crypto.md,
   What a `secrets.0` snapshot vouches for). A history add needs only the role
   its key names and a box only write, so a reader (Hp, at p) and a writer (Bp,
   at q) put entries at made-up epochs. Genuine rotations R1..R3 make g1..g3
   (R_k's keyset writes g_k and lists g_(k-1)); Gr is an admin's grant at g3,
   which may reach a node before R3 does. Admins A and C compact (at most Budget
   snapshots each); a node drops the bodies a snapshot covers as it writes or
   receives it. F, a reader, only receives. A holds every commit at first; the
   others get each commit from A while A holds it, and each snapshot from any
   holder, in any order. An entry is <<commit, epoch>>; a snapshot carries
   entries and covers commits. A node verifies e (established, names aside) by
   a held rotation commit of e or a held snapshot carrying an entry at e. Rule:
     "leaveout" the snapshot leaves out every entry at an epoch its writer has
                not verified, and covers a commit only when it carries all of
                its entries (the join-based cover): the rest stays beside. The
                build.
     "wait"     compact only while every keyed epoch is verified, carrying all.
     "all"      no gate: carry everything.
     "drop"     leave the unverified entries out and cover every held commit
                (they die wherever the snapshot goes).
     "keyset"   carry everything; a snapshot bases e only where a held keyset
                writes or lists e, and compaction waits only for those.
   NoLaunder: no node ever verifies a planted epoch. NoLoss: no node's live
   genuine entries ever shrink. Compacts: both admins compact. Based: every genuine
   epoch a node's state keys is eventually verified there (a fresh node too,
   once the rotation commits are dropped). Converge: every node ends with every
   entry. *)
EXTENDS Naturals, FiniteSets

CONSTANTS Rule, Budget

Admins == {"A", "C"}
Nodes == Admins \cup {"F"}
Rots == {"R1", "R2", "R3"}
Commits == Rots \cup {"Gr", "Hp", "Bp"}
Genuine == {"g1", "g2", "g3"}
Planted == {"p", "q"}
Idx == [c \in Rots |-> CASE c = "R1" -> 1 [] c = "R2" -> 2 [] c = "R3" -> 3]
G(k) == CASE k = 1 -> "g1" [] k = 2 -> "g2" [] k = 3 -> "g3"
Ent == [c \in Commits |-> CASE c \in Rots -> {G(Idx[c])}
                             [] c = "Gr" -> {"g3"}
                             [] c = "Hp" -> {"p"}
                             [] c = "Bp" -> {"q"}]
\* the keyset of rotation k: writes g_k, lists g_(k-1)
Ks(k) == IF k = 0 THEN {} ELSE {G(k)} \cup (IF k > 1 THEN {G(k - 1)} ELSE {})
AllEntries == UNION {{<<c, e>> : e \in Ent[c]} : c \in Commits}

VARIABLES held, snaps, made
vars == <<held, snaps, made>>

Max(S) == CHOOSE x \in S : \A y \in S : x >= y
Covered(n, c) == \E s \in snaps[n] : c \in s.covers
Dead(n, x) == \E s \in snaps[n] : x[1] \in s.covers /\ x \notin s.carried
Entries(n) == {x \in UNION {{<<c, e>> : e \in Ent[c]} : c \in held[n]} : ~Dead(n, x)}
              \cup UNION {s.carried : s \in snaps[n]}
Keyed(n) == {x[2] : x \in Entries(n)}
\* keys.0 at n: the newest keyset among held rotation commits and snapshots
KeysIdx(n) == Max({Idx[c] : c \in held[n] \cap Rots} \cup {s.ki : s \in snaps[n]} \cup {0})
KsNamed(n) == UNION {Ks(Idx[c]) : c \in held[n] \cap Rots} \cup Ks(KeysIdx(n))
SnapKeyed(n) == {x[2] : x \in UNION {s.carried : s \in snaps[n]}}
Verified(n, e) ==
  \/ \E c \in held[n] \cap Rots : G(Idx[c]) = e
  \/ e \in SnapKeyed(n) /\ (Rule = "keyset" => e \in KsNamed(n))

Init ==
  /\ held = [n \in Nodes |-> IF n = "A" THEN Commits ELSE {}]
  /\ snaps = [n \in Nodes |-> {}]
  /\ made = [n \in Admins |-> 0]

Compact(n) ==
  LET E == Entries(n)
      carried == IF Rule \in {"leaveout", "drop"} THEN {x \in E : Verified(n, x[2])} ELSE E
      covers == IF Rule = "leaveout"
                THEN {c \in held[n] : \A e \in Ent[c] : <<c, e>> \in carried}
                ELSE held[n]
      s == [by |-> n, k |-> made[n] + 1, carried |-> carried, covers |-> covers, ki |-> KeysIdx(n)]
  IN /\ made[n] < Budget
     /\ Rule = "wait" => \A x \in E : Verified(n, x[2])
     /\ Rule = "keyset" => \A x \in E : x[2] \in KsNamed(n) => Verified(n, x[2])
     /\ snaps' = [snaps EXCEPT ![n] = @ \cup {s}]
     /\ made' = [made EXCEPT ![n] = @ + 1]
     \* the bodies it covers go at once (the snapshot carries what they wrote)
     /\ held' = [held EXCEPT ![n] = @ \ covers]

\* a commit covered by a held snapshot is not joined (dropped on arrival)
Deliver(n, m, c) ==
  /\ n # m /\ c \in held[m] \ held[n] /\ ~Covered(n, c)
  /\ held' = [held EXCEPT ![n] = @ \cup {c}]
  /\ UNCHANGED <<snaps, made>>

\* a received snapshot drops the held bodies it covers at once
DeliverS(n, m, s) ==
  /\ n # m /\ s \in snaps[m] \ snaps[n]
  /\ snaps' = [snaps EXCEPT ![n] = @ \cup {s}]
  /\ held' = [held EXCEPT ![n] = @ \ s.covers]
  /\ UNCHANGED made

Next ==
  \/ \E n \in Admins : Compact(n)
  \/ \E n \in Nodes, c \in Commits : Deliver(n, "A", c)
  \/ \E n, m \in Nodes : \E s \in snaps[m] : DeliverS(n, m, s)

Fair ==
  /\ \A n \in Admins : WF_vars(Compact(n))
  /\ \A n \in Nodes, c \in Commits : WF_vars(Deliver(n, "A", c))
  /\ \A n, m \in Nodes : WF_vars(\E s \in snaps[m] : DeliverS(n, m, s))

Spec == Init /\ [][Next]_vars /\ Fair

NoLaunder == \A n \in Nodes, e \in Planted : ~Verified(n, e)
NoLoss == [][\A n \in Nodes : {x \in Entries(n) : x[2] \in Genuine} \subseteq Entries(n)']_vars
Compacts == <>(\A n \in Admins : made[n] >= 1)
Based == <>[](\A n \in Nodes, e \in Genuine : e \in Keyed(n) => Verified(n, e))
Converge == <>[](\A n \in Nodes : Entries(n) = AllEntries)
=============================================================================

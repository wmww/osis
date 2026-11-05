-------------------------------- MODULE Sides --------------------------------
(* Hosts and storage during a dispute (notes/owner-removal-plan.md step 6).   *)
(* Admins X and Y of actor A removed each other; each node takes a side and   *)
(* runs the ordinary sync rules (spec/sync.md §6-§7) over its side's          *)
(* validity. One host, one label L (a label where both sides act with the     *)
(* same keys), or with Fork a step race at L and a replacement label R for    *)
(* the side that lost it. Bodies are whole commits; crypto is access.         *)
(* Design exploration forked from ../sync, not an independent spec check.     *)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Nodes, Parties,   \* Parties: the nodes X and Y themselves (fixed side)
  InitSide,         \* [Nodes -> Sides]
  Switches,         \* how many side switches non-parties make in all
  Bodies,           \* commits, one body each, all written before the run
  Valid,            \* [Bodies -> SUBSET Sides]: sides on which it is valid
  Seed,             \* [Bodies -> BOOLEAN]: written by X or Y, unlisted by the
                    \*   other's removal (a direct seed of D on one side)
  Aspect,           \* [Bodies -> aspect name]
  Reasons,          \* [Bodies -> set of [w, pol, kind, purge]]:
                    \*   kind "not": must-not-hold while the reason holds
                    \*   kind "cover": covered while it holds (compaction)
                    \*   pol "valid": holds while w is valid; "invalid": while
                    \*   w is invalid (a fall, or a placement w that keeps it)
  InitHeld,         \* [Nodes -> SUBSET Bodies]
  InitHost,         \* SUBSET Bodies, under L
  RoleC,            \* role-class commits (placements): uploaded and fetched first
  Gate,             \* "none" | "direct" | "neutral" | "touch" | "exact" | "aspect"
  ReupOnce,         \* candidate (b): re-upload a deleted body once, then keep it local
  Fork,             \* candidate (c): the loser of the step race replaces L by R
  CoverOwn,         \* candidate (d): covers judged on the own side alone, ungated
  Bridge            \* with Fork: a member also uploads and deletes clean bodies
                    \*   at the label it reads but does not act at

Sides == {"X", "Y"}
Labels == {"L", "R"}
Other(s) == IF s = "X" THEN "Y" ELSE "X"
\* Dd: writes whose validity depends on the side (the closure of both
\* parties' unlisted writes; the walk can export it).
Dd == {w \in Bodies : Valid[w] # {} /\ Valid[w] # Sides}

VARIABLES side, held, applied, host, ever, head, rside, compacted, reup, sw
vars == <<side, held, applied, host, ever, head, rside, compacted, reup, sw>>

-----------------------------------------------------------------------------
(* Judgment in a view: side s, known commits K.                              *)
V(s, w) == s \in Valid[w]
\* A "valid" reason needs its write held; an "invalid" one also holds while
\* its write is not held (no placement held keeps nothing).
Holds(s, K, r) == IF r.pol = "valid" THEN r.w \in K /\ V(s, r.w)
                  ELSE r.w \notin K \/ ~V(s, r.w)
NHolds(K, r) == IF r.pol = "valid" THEN r.w \in K /\ Valid[r.w] = Sides
                ELSE r.w \notin K \/ Valid[r.w] # Sides
Rs(b, k) == {r \in Reasons[b] : r.kind = k}
NotOn(s, K, b) == \E r \in Rs(b, "not") : Holds(s, K, r)
CovOn(s, K, b) == \E r \in Rs(b, "cover") : Holds(s, K, r)
\* must-hold: valid, not must-not-hold, not covered (no keep-at-least here).
MustHold(s, K, b) == V(s, b) /\ ~NotOn(s, K, b) /\ ~CovOn(s, K, b)

\* An aspect touched by a disputed write: one of its writes, or a reason
\* write on one of its bodies (a purge naming it), is in Dd.
Touched(K, a) == \E b \in Bodies :
  Aspect[b] = a /\ (b \in K \cap Dd \/ \E r \in Reasons[b] : r.w \in K \cap Dd)

\* May node n delete b at a host for a reason of kind k (it judges b so)?
Gated(n, b, k) ==
  LET s == side[n]  K == applied[n]  R == Rs(b, k)
      Disp(w) == w \in K /\ w \in Dd IN
  CASE Gate = "none"    -> \E r \in R : Holds(s, K, r)
    [] Gate = "direct"  -> \E r \in R : Holds(s, K, r) /\ ~(r.w \in K /\ Seed[r.w])
    [] Gate = "neutral" -> (\E r \in R : Holds(s, K, r)) /\ (\E r \in R : NHolds(K, r))
    [] Gate = "touch"   -> ~Disp(b) /\ \E r \in R : Holds(s, K, r) /\ ~Disp(r.w)
    [] Gate = "exact"   -> \A t \in Sides : \E r \in R : Holds(t, K, r)
    [] Gate = "aspect"  -> (\E r \in R : Holds(s, K, r)) /\ ~Touched(K, Aspect[b])

\* Where a node acts (uploads, deletes): without Fork, at L. With Fork, at L
\* while its head is the pre-dispute step or its own side's, else at R once
\* its side made R. A node uses no key from a commit invalid on its side.
Acts(n, l) ==
  IF ~Fork THEN l = "L"
  ELSE \/ l = "L" /\ head \in {"pre", side[n]}
       \/ l = "R" /\ rside = side[n]
\* What it reads: a member holds both sides' boxes, a party its own side's.
Reads(n, l) == Acts(n, l) \/ (n \notin Parties /\ (l = "L" \/ rside # "none"))
\* A fresh node granted on side s after the dispute.
FreshReads(s, l) == IF ~Fork THEN l = "L"
                    ELSE \/ l = "L" /\ head \in {"pre", s}
                         \/ l = "R" /\ rside = s

\* Clean: neither the body nor a known reason write on it is disputed, so
\* every side judges it alike.
Clean(n, b) == b \notin Dd /\ \A r \in Reasons[b] : r.w \in applied[n] => r.w \notin Dd
\* With Bridge, a member acts on clean bodies at every label it reads.
ActsOn(n, l, b) == Acts(n, l) \/ (Bridge /\ n \notin Parties /\ Reads(n, l) /\ Clean(n, b))

-----------------------------------------------------------------------------
Init ==
  /\ side = InitSide
  /\ held = InitHeld
  /\ applied = InitHeld
  /\ host = [l \in Labels |-> IF l = "L" THEN InitHost ELSE {}]
  /\ ever = [l \in Labels |-> IF l = "L" THEN InitHost ELSE {}]
  /\ head = "pre"
  /\ rside = "none"
  /\ compacted = [n \in Nodes |-> {}]
  /\ reup = [n \in Nodes |-> {}]
  /\ sw = 0

\* Cursor sync: a new entry, or one dropped before that it now must hold;
\* role-class entries first (sync §6 first sync: order 0 before the rest).
Recv(n, l, b) ==
  /\ Reads(n, l) /\ b \in host[l] /\ b \notin held[n]
  /\ b \notin RoleC => host[l] \cap RoleC \subseteq applied[n]
  /\ b \notin applied[n] \/ MustHold(side[n], applied[n], b)
  /\ held' = [held EXCEPT ![n] = @ \cup {b}]
  /\ applied' = [applied EXCEPT ![n] = @ \cup {b}]
  /\ UNCHANGED <<side, host, ever, head, rside, compacted, reup, sw>>

\* Local drop of a must-not-hold or covered body (own side, never gated).
Drop(n, b) ==
  /\ b \in held[n]
  /\ NotOn(side[n], applied[n], b) \/ CovOn(side[n], applied[n], b)
  /\ held' = [held EXCEPT ![n] = @ \ {b}]
  /\ UNCHANGED <<side, applied, host, ever, head, rside, compacted, reup, sw>>

\* sync §6: upload every must-hold body the label lacks, role commits first
\* (notes/sync.md pass order). (b): a body once
\* deleted there is uploaded again at most once by each node.
Upload(n, l, b) ==
  /\ ActsOn(n, l, b) /\ b \in held[n] /\ b \notin host[l]
  /\ MustHold(side[n], applied[n], b)
  /\ b \notin RoleC => {c \in held[n] \cap RoleC : MustHold(side[n], applied[n], c)} \subseteq host[l]
  /\ ReupOnce => (b \notin ever[l] \/ b \notin reup[n])
  /\ host' = [host EXCEPT ![l] = @ \cup {b}]
  /\ ever' = [ever EXCEPT ![l] = @ \cup {b}]
  /\ reup' = IF b \in ever[l] THEN [reup EXCEPT ![n] = @ \cup {b}] ELSE reup
  /\ UNCHANGED <<side, held, applied, head, rside, compacted, sw>>

\* sync §6: delete-key holders delete must-not-hold bodies, every time.
Delete(n, l, b) ==
  /\ ActsOn(n, l, b) /\ b \in host[l] /\ b \in applied[n]
  /\ Gated(n, b, "not")
  /\ host' = [host EXCEPT ![l] = @ \ {b}]
  /\ UNCHANGED <<side, held, applied, ever, head, rside, compacted, reup, sw>>

\* sync §7: compaction deletes a covered body once per body, with a
\* covering snapshot under the label. Optional (unfair).
Compact(n, l, b) ==
  /\ Acts(n, l) /\ b \in host[l] /\ b \in applied[n] /\ b \notin compacted[n]
  /\ ~NotOn(side[n], applied[n], b)
  /\ \E r \in Rs(b, "cover") : Holds(side[n], applied[n], r) /\ r.w \in host[l]
  /\ CoverOwn \/ Gated(n, b, "cover")
  /\ host' = [host EXCEPT ![l] = @ \ {b}]
  /\ compacted' = [compacted EXCEPT ![n] = @ \cup {b}]
  /\ UNCHANGED <<side, held, applied, ever, head, rside, reup, sw>>

\* A member overrides its side (the parties keep theirs).
Switch(n) ==
  /\ n \notin Parties /\ sw < Switches
  /\ side' = [side EXCEPT ![n] = Other(@)]
  /\ sw' = sw + 1
  /\ UNCHANGED <<held, applied, host, ever, head, rside, compacted, reup>>

\* (c): the parties' rotations race for L's next step; the first wins.
Register(p) ==
  /\ Fork /\ p \in Parties /\ head = "pre"
  /\ head' = side[p]
  /\ UNCHANGED <<side, held, applied, host, ever, rside, compacted, reup, sw>>
\* The loser replaces L by R (spec/sync.md §2, keys from its side's secrets).
\* It deletes nothing at L: it does not control L's head there.
Replace(p) ==
  /\ Fork /\ p \in Parties /\ head \notin {"pre", side[p]} /\ rside = "none"
  /\ rside' = side[p]
  /\ UNCHANGED <<side, held, applied, host, ever, head, compacted, reup, sw>>

Next ==
  \/ \E n \in Nodes :
       \/ Switch(n) \/ Register(n) \/ Replace(n)
       \/ \E b \in Bodies : Drop(n, b)
       \/ \E l \in Labels, b \in Bodies :
            Recv(n, l, b) \/ Upload(n, l, b) \/ Delete(n, l, b) \/ Compact(n, l, b)

Fairness ==
  \A n \in Nodes :
    /\ WF_vars(Register(n)) /\ WF_vars(Replace(n))
    /\ \A b \in Bodies :
         /\ WF_vars(Drop(n, b))
         /\ WF_vars(\E l \in Labels : Recv(n, l, b))
         /\ WF_vars(\E l \in Labels : Upload(n, l, b))
         /\ WF_vars(\E l \in Labels : Delete(n, l, b))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties. G: judged with every commit known.                            *)
GLive(s, b) == MustHold(s, Bodies, b)
Copy(b) == (\E n \in Nodes : b \in held[n]) \/ (\E l \in Labels : b \in host[l])
OnSide(s) == \E n \in Nodes : side[n] = s

TypeOK == /\ side \in [Nodes -> Sides] /\ head \in {"pre"} \cup Sides
          /\ rside \in {"none"} \cup Sides
          /\ \A n \in Nodes : held[n] \subseteq applied[n]

\* No host delete loses a body some side keeps live: once a body reached a
\* host, a copy stays while any side would keep it live.
NoLoss == \A b \in Bodies :
  ((\E l \in Labels : b \in ever[l]) /\ \E s \in Sides : GLive(s, b)) => Copy(b)

\* No endless upload/delete alternation: the host settles.
Quiesce == <>[][host' = host]_vars

\* A fresh node on a side some node is on finds there every body that side
\* keeps live and someone still has.
Served == <>[](\A s \in Sides, b \in Bodies :
  (OnSide(s) /\ GLive(s, b) /\ Copy(b)) => \E l \in Labels : FreshReads(s, l) /\ b \in host[l])

\* After its switches, a node holds alike with a fresh node of its side.
FreshSet(s) == {b \in Bodies : GLive(s, b) /\ \E l \in Labels : FreshReads(s, l) /\ b \in host[l]}
Alike == <>[](\A n \in Nodes :
  {b \in held[n] : GLive(side[n], b)} = FreshSet(side[n]))

\* A purge every side accepts reaches the host: no purged body stays.
PurgePrompt == <>[](\A l \in Labels : \A b \in host[l] :
  ~\E r \in Reasons[b] : r.purge /\ r.kind = "not" /\ Valid[r.w] = Sides)
=============================================================================

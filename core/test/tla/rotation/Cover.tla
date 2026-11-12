-------------------------------- MODULE Cover --------------------------------
(* Which epochs cover a departure (spec/crypto.md §4 Names, Covers: the     *)
(* pin). One actor, read role. First admin O and admin P are honest; L is *)
(* an admin that leaves by self-removal (S) and may forge: a history entry at *)
(* an epoch it holds listing S, a backdated rotation (valid: it was admin at  *)
(* that ts) listing S, or a rotation in S itself. With Audit, the audit-drop *)
(* shape: P demotes L to read (K), L self-removes (S), O removes P (D) and   *)
(* its audit drops K; admin Q may hold D without S and rotate for P.         *)
(* Only the entry the rotation commit wrote counts (bound by                 *)
(* the keyset's names hash), and only while that commit's author holds the   *)
(* role; the same for a departure the rotation commit itself makes.          *)
(* Covers is the pin: over the tail of the holder's edge (its writes after   *)
(* the newest applied one giving read), a write taking it to none that takes *)
(* here (applies, or would over the edge before it) named applied or made by *)
(* the rotation commit itself, and every write giving read that counts (its  *)
(* author held write at its point) and applies nothing here named void ("^"  *)
(* before its id). Names: applied lowerings, and void writes that count and  *)
(* give a role. With Dup, Q removes L concurrently with S (S2, carrying Q's   *)
(* rotation, which leaves L out), so S2 applies nothing where S is held.     *)
(* Regrant: O removes reader-admin M (Rm), then demotes P to DemoteTo (Dp);  *)
(* P, not holding Dp, may remove M itself (W) and re-grant it (Gr), boxing M *)
(* at its current epochs (P acts so even when not a writer, from what it     *)
(* holds: PKnows at the start); both are ordered after Dp, so they apply     *)
(* nothing where Dp is held (invalid, not audited). Else: Dp takes P's right *)
(* through a holder actor, so no rotation of this actor names it, and honest *)
(* writers re-seal holders they see unboxed at a current epoch they hold.    *)
(* KeylessHolds (negative control): L, gone, still counts as holding the     *)
(* role (spec/crypto.md §4 Holds counting a keyless grant's path).          *)
(* MetVoid: a void name is met only where its write applies nothing (FALSE:  *)
(* the negative control).                                                    *)
(* Commits are delivered whole in any order; boxes are global (crypto is     *)
(* access: a party's secrets are the closure over boxes to it and history).  *)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS Forge, Audit, Writers, MaxE, Dup, Regrant, DemoteTo, PKnows, Else, MetVoid, KeylessHolds

Honest == Writers
Members == {"P", "L", "Q"} \cup (IF Regrant THEN {"M"} ELSE {})
Parties == {"O"} \cup Members
ADMIN == 3
WRITE == 2
READ == 1
NONE == 0

K == [id |-> "K", ts |-> 5, author |-> "P", h |-> "L", val |-> READ, kind |-> "chg"]
S == [id |-> "S", ts |-> 9, author |-> "L", h |-> "L", val |-> NONE, kind |-> "self"]
D == [id |-> "D", ts |-> 11, author |-> "O", h |-> "P", val |-> NONE, kind |-> "chg"]
Rm == [id |-> "Rm", ts |-> 3, author |-> "O", h |-> "M", val |-> NONE, kind |-> "chg"]
Dp == [id |-> "Dp", ts |-> 12, author |-> "O", h |-> "P", val |-> DemoteTo, kind |-> "chg"]
Static == {S} \cup (IF Audit THEN {K, D} ELSE {}) \cup (IF Regrant THEN {Rm, Dp} ELSE {})
StaticIds == {c.id : c \in Static}

VARIABLES cs,      \* edge and rotation commits that exist
          held,    \* held[n]: commit ids node n holds (L holds everything)
          eps,     \* epochs; eps[i + 1] has id i
          ents,    \* history entries: [e, author, names, bound]
          boxes,   \* {<<party, epoch id>>}
          adds,    \* history adds {<<epoch id, earlier epoch id>>}: an entry at e carries f
          wrote,   \* {<<epoch id, holders the writer saw departed, held Gr>>}
          forged   \* forgeries made (each once)
vars == <<cs, held, eps, ents, boxes, adds, wrote, forged>>

Ep(i) == eps[i + 1]
EpIds == 0 .. Len(eps) - 1
AllIds == {c.id : c \in cs}
CommitOf(id) == CHOOSE c \in cs : c.id = id

\* ---- the role timeline at a node holding H ---------------------------------
\* O's demotion of P (D) audits P: its frontier holds none of P's writes, so every
\* write of P before it is dropped wherever D is held.
Dropped(H, c) == c.author = "P" /\ c.kind = "chg" /\ "D" \in H /\ c.ts < D.ts

RECURSIVE Sorted(_)
Sorted(X) == IF X = {} THEN <<>>
             ELSE LET m == CHOOSE c \in X : \A d \in X : c.ts <= d.ts
                  IN <<m>> \o Sorted(X \ {m})

Init0 == [edge |-> [h \in Members |-> ADMIN], low |-> {}, ap |-> {}, pre |-> <<>>]

\* an explicit change applies by its author's admin (O always); a self-removal always
Applies(st, c) == IF c.kind = "self" \/ c.author = "O" THEN TRUE ELSE st.edge[c.author] = ADMIN
\* a dropped write applies nothing; pre: each walked write's edges just before it
Step(H, st, c) ==
  LET ok == ~Dropped(H, c) /\ Applies(st, c)
      new == IF ok THEN [st.edge EXCEPT ![c.h] = c.val] ELSE st.edge
  IN [edge |-> new,
      low |-> st.low \cup (IF ok /\ new[c.h] < st.edge[c.h] THEN {c.id} ELSE {}),
      ap |-> st.ap \cup (IF ok THEN {c.id} ELSE {}),
      pre |-> st.pre @@ (c.id :> st.edge)]

RECURSIVE WalkSeq(_, _, _)
WalkSeq(H, st, s) == IF s = <<>> THEN st ELSE WalkSeq(H, Step(H, st, Head(s)), Tail(s))
Edge(H) == {c \in cs : c.kind \in {"chg", "self"} /\ c.id \in H}
Walk(H) == WalkSeq(H, Init0, Sorted(Edge(H)))
\* the edges just before c's point
Before(H, c) == [edge |-> Walk(H).pre[c.id]]

\* ---- the pin (spec/crypto.md §4 Covers) --------------------------------------
\* the held writes on h's edge, dropped ones included (they apply nothing), in ts order
Writes(H, h) == Sorted({c \in cs : c.kind \in {"chg", "self"} /\ c.id \in H /\ c.h = h})
Ap(H, c) == c.id \in Walk(H).ap
\* applying nothing, its author held write at its point
Counts(H, c) == ~Ap(H, c) /\ (IF c.author = "O" THEN TRUE ELSE Before(H, c).edge[c.author] >= WRITE)
\* it takes the holder down: it applies, or would over the edge before it (not dropped)
Takes(H, c) == Ap(H, c) \/ (~Dropped(H, c) /\ Applies(Before(H, c), c))
VName(id) == "^" \o id
OfName(x) == CHOOSE c \in cs : c.id = x \/ VName(c.id) = x
IsVoid(x) == x # OfName(x).id
\* the names a rotation by a node holding H writes
NamesOf(H) == {id \in Walk(H).low : ~(Else /\ id = "Dp")}
              \cup {VName(c.id) : c \in {d \in cs : d.kind \in {"chg", "self"} /\ d.id \in H /\ d.val >= READ /\ Counts(H, d) /\ ~(Else /\ d.id = "Dp")}}
\* names pin h below read at a node holding H; mark: the rotation commit's id, its author held
Pins(H, names, h, mark, markOk) ==
  LET ws == Writes(H, h)
      gs == {i \in 1 .. Len(ws) : Ap(H, ws[i]) /\ ws[i].val >= READ}
      g == IF gs = {} THEN 0 ELSE CHOOSE i \in gs : \A j \in gs : j <= i
      tail == {i \in 1 .. Len(ws) : i > g}
  IN /\ \E i \in tail : ws[i].val < READ /\ Takes(H, ws[i]) /\ (ws[i].id \in names \/ (ws[i].id = mark /\ markOk))
     /\ \A i \in tail : (ws[i].val >= READ /\ Counts(H, ws[i])) => VName(ws[i].id) \in names

\* ---- keys at a node ---------------------------------------------------------
RECURSIVE Close(_)
Close(X) == LET T == X \cup UNION {Ep(e).hist : e \in X} \cup {p[2] : p \in {q \in adds : q[1] \in X}}
            IN IF T = X THEN X ELSE Close(T)
Sec(p) == Close({e \in EpIds : <<p, e>> \in boxes})

Met(n, names) == \A x \in names : OfName(x).id \in held[n]
                   /\ (MetVoid /\ IsVoid(x) => OfName(x).id \notin Walk(held[n]).ap)
Est(n, e) == e = 0 \/ (Ep(e).commit \in held[n]
                       /\ (e \in Sec(n) => \E x \in ents : x.e = e /\ Met(n, x.names)))
EstSet(n) == {e \in EpIds : Est(n, e)}
Current(n) == {e \in EstSet(n) : ~\E f \in EstSet(n) : e \in Ep(f).lists}
\* Unsuperseded: current were the names condition of Est dropped
RotSet(n) == {e \in EpIds : e = 0 \/ Ep(e).commit \in held[n]}
Unsup(n) == {e \in RotSet(n) : ~\E f \in RotSet(n) : e \in Ep(f).lists}
Newest(n) == CHOOSE e \in Current(n) : \A f \in Current(n) :
               Ep(e).num > Ep(f).num \/ (Ep(e).num = Ep(f).num /\ e <= f)

Role(n, p) == IF p = "O" THEN ADMIN ELSE Walk(held[n]).edge[p]
Holds(n, p) == Role(n, p) >= READ
\* whether a rotator's word counts (Covers): Holds, or with KeylessHolds L anyway
AuthHolds(n, p) == Holds(n, p) \/ (KeylessHolds /\ p = "L")
Departed(n) == {h \in Members : Role(n, h) = NONE}

\* Covers (spec/crypto.md §4): the departure of h at n by epoch e: a met bound entry pins it; an
\* epoch whose secret n lacks covers nothing (its history box is closed to it)
Covers(n, e, h) ==
  LET ep == Ep(e)
  IN /\ e \in Sec(n) /\ AuthHolds(n, ep.author)
     /\ \E x \in ents : x.e = e /\ x.bound /\ Met(n, x.names) /\ Pins(held[n], x.names, h, ep.commit, AuthHolds(n, ep.author))
CoversAll(n, e) == \A h \in Departed(n) : Covers(n, e, h)
NeedRot(n) == \E e \in Current(n) : ~CoversAll(n, e)
\* withdraw: an unsuperseded epoch not current at n, by its maker, or by anyone when its maker
\* may not rotate
Withdraw(n) == \E e \in Unsup(n) \ Current(n) : Ep(e).author = n \/ Role(n, Ep(e).author) < ADMIN
HasCurrent(n) == Current(n) \cap Sec(n) # {}
MayEncrypt(n) == HasCurrent(n) /\ Newest(n) \in Sec(n) /\ ~NeedRot(n)

Holders(n) == {p \in Parties : Holds(n, p)}
NewEpoch(n, cid, author) ==
  LET ls == Current(n) \cup Unsup(n)
  IN [id |-> Len(eps), num |-> 1 + Ep(CHOOSE e \in ls : \A f \in ls : Ep(e).num >= Ep(f).num).num,
      commit |-> cid, author |-> author, lists |-> ls, hist |-> EstSet(n) \cap Sec(n)]

\* ---- actions ----------------------------------------------------------------
Deliver(n) == \E c \in cs : c.id \notin held[n] /\ held' = [held EXCEPT ![n] = @ \cup {c.id}]
              /\ UNCHANGED <<cs, eps, ents, boxes, adds, forged>>

\* rotating needs only the right to rotate (no current secret): the history box carries the
\* established secrets n holds
HonestRots == Cardinality({c \in cs : c.kind = "rot" /\ c.author \in Honest})
\* a rotator holds the role in its own view (one that does not makes no valid rotation; a box it
\* writes anyway carries only what it held, a stated limit)
Rotate(n) ==
  /\ (NeedRot(n) \/ Withdraw(n)) /\ HonestRots < MaxE /\ Role(n, n) = ADMIN
  /\ LET id == "R" \o ToString(Len(eps))
         e == NewEpoch(n, id, n)
     IN /\ cs' = cs \cup {[id |-> id, ts |-> 20 + Len(eps), author |-> n, kind |-> "rot"]}
        /\ held' = [held EXCEPT ![n] = @ \cup {id}, !["L"] = @ \cup {id}]
        /\ eps' = Append(eps, e)
        /\ ents' = ents \cup {[e |-> e.id, author |-> n, names |-> NamesOf(held[n]), bound |-> TRUE]}
        /\ boxes' = boxes \cup {<<p, e.id>> : p \in Holders(n)}
  /\ UNCHANGED <<forged, adds>>

\* what the entries at e carry
ListedAt(e) == Ep(e).hist \cup {p[2] : p \in {q \in adds : q[1] = e}}
\* a history add (spec/crypto.md §4, History box): n holds an earlier established secret no
\* entry at a current epoch it holds and may encrypt under lists; the new entry copies the
\* names of a met entry bound to the epoch's commit
HistAdd(n) ==
  /\ \E e \in Current(n) \cap Sec(n) :
       /\ CoversAll(n, e)
       /\ LET missing == {f \in (EstSet(n) \cap Sec(n)) \ Current(n) : Ep(f).num < Ep(e).num /\ f \notin ListedAt(e)}
          IN /\ missing # {}
             /\ adds' = adds \cup {<<e, f>> : f \in missing}
             /\ \E x \in ents : x.e = e /\ x.bound /\ Met(n, x.names)
                  /\ ents' = ents \cup {[e |-> e, author |-> n, names |-> x.names, bound |-> TRUE]}
  /\ UNCHANGED <<cs, held, eps, boxes, forged>>

\* L puts an entry at an epoch it holds, listing S (and all it holds, so the names are met).
ForgeEntry ==
  /\ "entry" \in Forge
  /\ \E e \in Sec("L") : <<"entry", e>> \notin forged
       /\ ents' = ents \cup {[e |-> e, author |-> "L", names |-> {"S"}, bound |-> FALSE]}
       /\ forged' = forged \cup {<<"entry", e>>}
  /\ UNCHANGED <<cs, held, eps, boxes, adds>>

\* L rotates in a commit backdated before S (ts 8: it was admin), listing S; it boxes the
\* holders its view shows and itself (boxing a party it knows departed is handing it the
\* secret out of band: nothing the covers rule judges).
ForgeBackdated ==
  /\ "backdated" \in Forge /\ <<"backdated", 0>> \notin forged
  /\ HasCurrent("L")
  /\ LET e == NewEpoch("L", "B", "L")
     IN /\ cs' = cs \cup {[id |-> "B", ts |-> 8, author |-> "L", kind |-> "rot"]}
        /\ held' = [held EXCEPT !["L"] = @ \cup {"B"}]
        /\ eps' = Append(eps, e)
        /\ ents' = ents \cup {[e |-> e.id, author |-> "L", names |-> {"S"}, bound |-> TRUE]}
        /\ boxes' = boxes \cup {<<p, e.id>> : p \in Holders("L") \cup {"L"}}
        /\ forged' = forged \cup {<<"backdated", 0>>}
  /\ UNCHANGED adds

\* S itself carries a rotation by L (its departs mark names itself): boxes the holders L's
\* view shows but itself; L made it.
SelfRot ==
  /\ "selfrot" \in Forge /\ <<"selfrot", 0>> \notin forged
  /\ HasCurrent("L")
  /\ LET e == NewEpoch("L", "S", "L")
     IN /\ eps' = Append(eps, e)
        /\ ents' = ents \cup {[e |-> e.id, author |-> "L", names |-> {}, bound |-> TRUE]}
        /\ boxes' = boxes \cup {<<p, e.id>> : p \in Holders("L") \cup {"L"}}
        /\ forged' = forged \cup {<<"selfrot", 0>>}
  /\ UNCHANGED <<cs, held, adds>>

\* Q removes L not knowing S (Dup), in a commit carrying its rotation: it boxes the holders
\* its view shows but L; its departs mark names S2 itself
DupRemoval ==
  /\ Dup /\ "S2" \notin AllIds /\ "S" \notin held["Q"] /\ HasCurrent("Q") /\ Role("Q", "Q") = ADMIN
  /\ LET e == NewEpoch("Q", "S2", "Q")
     IN /\ cs' = cs \cup {[id |-> "S2", ts |-> 20 + Len(eps), author |-> "Q", h |-> "L", val |-> NONE, kind |-> "chg"]}
        /\ held' = [held EXCEPT !["Q"] = @ \cup {"S2"}, !["L"] = @ \cup {"S2"}]
        /\ eps' = Append(eps, e)
        /\ ents' = ents \cup {[e |-> e.id, author |-> "Q", names |-> NamesOf(held["Q"]), bound |-> TRUE]}
        /\ boxes' = boxes \cup {<<p, e.id>> : p \in Holders("Q") \ {"L"}}
  /\ UNCHANGED <<forged, adds>>

\* P, not holding Dp, removes M (W) while its view shows M holding (Regrant)
PRemove ==
  /\ Regrant /\ "W" \notin AllIds /\ Role("P", "P") = ADMIN /\ Holds("P", "M")
  /\ cs' = cs \cup {[id |-> "W", ts |-> 40 + Len(eps), author |-> "P", h |-> "M", val |-> NONE, kind |-> "chg"]}
  /\ held' = [held EXCEPT !["P"] = @ \cup {"W"}, !["L"] = @ \cup {"W"}]
  /\ UNCHANGED <<eps, ents, boxes, adds, forged>>
\* P, not holding Dp, re-grants M read while its view shows M departed, boxing M at the current
\* epochs it holds (Regrant)
ReGrant ==
  /\ Regrant /\ "Gr" \notin AllIds /\ Role("P", "P") = ADMIN /\ Role("P", "M") = NONE
  /\ cs' = cs \cup {[id |-> "Gr", ts |-> 41 + Len(eps), author |-> "P", h |-> "M", val |-> READ, kind |-> "chg"]}
  /\ held' = [held EXCEPT !["P"] = @ \cup {"Gr"}, !["L"] = @ \cup {"Gr"}]
  /\ boxes' = boxes \cup {<<"M", e>> : e \in Current("P") \cap Sec("P")}
  /\ UNCHANGED <<eps, ents, adds, forged>>

\* an honest writer re-seals a holder its view shows without a box at a current epoch it
\* holds (Else)
Reseal(n) ==
  /\ Else /\ Role(n, n) >= WRITE
  /\ \E e \in Current(n) \cap Sec(n) : \E p \in Holders(n) : <<p, e>> \notin boxes
       /\ boxes' = boxes \cup {<<p, e>>}
  /\ UNCHANGED <<cs, held, eps, ents, adds, forged>>

\* each write: its epoch, the holders its writer saw departed, whether it held P's re-grant
WritesNow == {<<Newest(n), Departed(n), "Gr" \in held[n]>> : n \in {m \in Honest : MayEncrypt(m)}}

E0 == [id |-> 0, num |-> 0, commit |-> "G", author |-> "O", lists |-> {}, hist |-> {}]
Init == /\ cs = Static
        /\ held = [n \in Parties |-> IF n = "L" THEN StaticIds ELSE IF n = "P" THEN PKnows ELSE {}]
        /\ eps = <<E0>>
        /\ ents = {[e |-> 0, author |-> "O", names |-> {}, bound |-> TRUE]}
        /\ boxes = {<<p, 0>> : p \in Parties}
        /\ adds = {}
        /\ wrote = {}
        /\ forged = {}
Next == /\ \/ \E n \in Honest : Deliver(n) \/ Rotate(n) \/ HistAdd(n) \/ Reseal(n)
           \/ ForgeEntry \/ ForgeBackdated \/ SelfRot \/ DupRemoval \/ PRemove \/ ReGrant
        /\ wrote' = wrote \cup WritesNow
Spec == Init /\ [][Next]_vars

\* ---- properties -------------------------------------------------------------
TrulyDeparted == {h \in Members : Walk(AllIds).edge[h] = NONE}
\* content a writer wrote knowing a departure is never readable by the departed holder; what
\* hostile L holds it can hand any party out of band (its forgeries only automate that), so
\* another departed party reading an epoch L holds is no leak the rule judges; nor is M reading
\* what a writer not holding P's re-grant wrote (a grant the writer has not received hands on
\* what its author held, as a valid one would)
NoLeak == \A w \in wrote \cup WritesNow : \A m \in w[2] \cap TrulyDeparted :
            w[1] \notin Sec(m) \/ (m # "L" /\ w[1] \in Sec("L")) \/ (m = "M" /\ ~w[3])
\* Q's concurrent removal covers L's departure wherever S is held too (Dup: S2 applies nothing
\* there but would over the edge before it; else every node knowing both rotates again), where
\* its names are met (a covering entry's are)
DupCovers == \A n \in Honest : \A e \in EpIds :
               (Ep(e).commit = "S2" /\ {"S", "S2"} \subseteq held[n] /\ e \in Sec(n) /\ Holds(n, "Q")
                /\ \E x \in ents : x.e = e /\ Met(n, x.names)) => Covers(n, e, "L")
\* Liveness is not modelled: a node holding everything covers all it knows by one rotation,
\* so the honest rotations are bounded by the departures and forgeries each node learns of
\* after the others' rotations; MaxE bounds them for the search.
================================================================================

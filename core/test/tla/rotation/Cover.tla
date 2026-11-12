-------------------------------- MODULE Cover --------------------------------
(* Which epochs cover a departure (spec/crypto.md §4 Names, Attributes,      *)
(* Covers). One actor, read role. First admin O and admin P are honest; L is *)
(* an admin that leaves by self-removal (S) and may forge: a history entry at *)
(* an epoch it holds listing S, a backdated rotation (valid: it was admin at  *)
(* that ts) listing S, or a rotation in S itself. With Audit, the audit-drop *)
(* shape: P demotes L to read (K), L self-removes (S), O removes P (D) and   *)
(* its audit drops K; admin Q may hold D without S and rotate for P.         *)
(* Only the entry the rotation commit wrote counts (bound by                 *)
(* the keyset's names hash), and only while that commit's author holds the   *)
(* role; the same for a departure the rotation commit itself makes.          *)
(* Attr "any": a departure is attributed to the newest held commit that      *)
(* lowered the holder or whose audit dropped a write on its edge; "lowering":*)
(* to the newest at whose point the holder's grant for keys was lowered.     *)
(* Later: also to each held commit after that one writing the holder's edge *)
(* to none, applied or not; with Dup, Q removes L concurrently with S (S2,   *)
(* carrying Q's rotation, which leaves L out), so S2 applies nothing where S *)
(* is held and covers only by Later.                                         *)
(* Regrant: O removes reader-admin M (Rm), then demotes P to DemoteTo (Dp);  *)
(* P, not holding Dp, may remove M itself (W) and re-grant it (Gr), boxing M *)
(* at its current epochs (P acts so even when not a writer, from what it     *)
(* holds: PKnows at the start); both are ordered after Dp, so they apply     *)
(* nothing where Dp is held (invalid, not audited). Raise: a held edge write *)
(* raising its holder that applies nothing, by an author holding write at   *)
(* its point, is a lowering at that point, named by itself as a raise ("^"  *)
(* before its id: never the name of the same commit applied as a lowering;  *)
(* Marked FALSE: the same name, the negative control). Else: Dp takes P's   *)
(* right through a holder actor, so no rotation of this actor names it, and *)
(* honest writers re-seal holders they see unboxed at a current epoch they  *)
(* hold. MetRaise: a raise name is met only where that raise applies nothing *)
(* either (FALSE: the negative control).                                     *)
(* Commits are delivered whole in any order; boxes are global (crypto is     *)
(* access: a party's secrets are the closure over boxes to it and history).  *)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS Attr, Forge, Audit, Writers, MaxE, Later, Dup, Regrant, Raise, DemoteTo, Marked, PKnows, Else, MetRaise

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

Init0 == [edge |-> [h \in Members |-> ADMIN], low |-> {}, unap |-> {}, ap |-> {}, attr |-> [h \in Members |-> "none"]]

\* an explicit change applies by its author's admin (O always); a self-removal always
Applies(st, c) == c.kind = "self" \/ c.author = "O" \/ st.edge[c.author] = ADMIN
Step(st, c) ==
  LET ok == Applies(st, c)
      new == IF ok THEN [st.edge EXCEPT ![c.h] = c.val] ELSE st.edge
      lowered == ok /\ new[c.h] < st.edge[c.h]
  IN [edge |-> new,
      low |-> st.low \cup (IF lowered THEN {c.id} ELSE {}),
      unap |-> st.unap \cup (IF ~ok /\ c.val > st.edge[c.h] /\ (c.author = "O" \/ st.edge[c.author] >= WRITE) THEN {c.id} ELSE {}),
      ap |-> st.ap \cup (IF ok THEN {c.id} ELSE {}),
      attr |-> [h \in Members |-> IF lowered /\ h = c.h THEN c.id ELSE st.attr[h]]]

RECURSIVE WalkSeq(_, _)
WalkSeq(st, s) == IF s = <<>> THEN st ELSE WalkSeq(Step(st, Head(s)), Tail(s))
Edge(H) == {c \in cs : c.kind \in {"chg", "self"} /\ c.id \in H /\ ~Dropped(H, c)}
Walk(H) == WalkSeq(Init0, Sorted(Edge(H)))

\* a raise applying nothing at a node holding H, by an author holding write at its point (Raise)
RaiseEv(H) == IF Raise THEN Walk(H).unap ELSE {}
\* its name, and the commit a name is of
RName(id) == IF Marked THEN "^" \o id ELSE id
OfName(x) == CHOOSE c \in cs : c.id = x \/ RName(c.id) = x
\* a drop event: D held with a dropped write on the holder's edge (Attr "any")
DropsOn(H, h) == "D" \in H /\ \E c \in cs : c.id \in H /\ Dropped(H, c) /\ c.h = h
\* the name a node holding H attributes h's departure to
AttrOf(H, h) == LET W == Walk(H)
                    lowers == IF W.attr[h] = "none" THEN {} ELSE {W.attr[h]}
                    cands == lowers \cup {RName(id) : id \in {i \in RaiseEv(H) : CommitOf(i).h = h}}
                             \cup (IF Attr = "any" /\ DropsOn(H, h) THEN {"D"} ELSE {})
                IN IF cands = {} THEN "none"
                   ELSE CHOOSE c \in cands : \A d \in cands : OfName(c).ts >= OfName(d).ts
\* every name h's departure is attributed to at a node holding H (Later: the commits after
\* AttrOf writing h's edge to none, applied or not)
AttrSet(H, h) == LET a == AttrOf(H, h)
                 IN IF a = "none" THEN {}
                    ELSE {a} \cup (IF Later THEN {c.id : c \in {d \in cs : d.id \in H /\ d.kind \in {"chg", "self"}
                                                      /\ d.h = h /\ d.val = NONE /\ d.ts > OfName(a).ts}} ELSE {})
\* the names a rotation by a node holding H writes
NamesOf(H) == (Walk(H).low \ (IF Else THEN {"Dp"} ELSE {})) \cup {RName(id) : id \in RaiseEv(H)} \cup (IF Attr = "any" /\ \E h \in Members : DropsOn(H, h) THEN {"D"} ELSE {})

\* ---- keys at a node ---------------------------------------------------------
RECURSIVE Close(_)
Close(X) == LET T == X \cup UNION {Ep(e).hist : e \in X} \cup {p[2] : p \in {q \in adds : q[1] \in X}}
            IN IF T = X THEN X ELSE Close(T)
Sec(p) == Close({e \in EpIds : <<p, e>> \in boxes})

IsRaise(x) == Marked /\ x # OfName(x).id
Met(n, names) == \A x \in names : OfName(x).id \in held[n]
                   /\ (MetRaise /\ IsRaise(x) => OfName(x).id \notin Walk(held[n]).ap)
Est(n, e) == e = 0 \/ (Ep(e).commit \in held[n]
                       /\ (e \in Sec(n) => \E x \in ents : x.e = e /\ Met(n, x.names)))
EstSet(n) == {e \in EpIds : Est(n, e)}
Current(n) == {e \in EstSet(n) : ~\E f \in EstSet(n) : e \in Ep(f).lists}
Newest(n) == CHOOSE e \in Current(n) : \A f \in Current(n) :
               Ep(e).num > Ep(f).num \/ (Ep(e).num = Ep(f).num /\ e <= f)

Role(n, p) == IF p = "O" THEN ADMIN ELSE Walk(held[n]).edge[p]
Holds(n, p) == Role(n, p) >= READ
Departed(n) == {h \in Members : Role(n, h) = NONE}

\* Covers (spec/crypto.md §4): the departure of h, attributed at n, by epoch e; an epoch
\* whose secret n lacks covers nothing (its history box is closed to it)
Covers(n, e, h) ==
  LET A == AttrSet(held[n], h)
      ep == Ep(e)
      ByEntry == \E x \in ents : x.e = e /\ Met(n, x.names) /\ A \cap x.names # {}
                   /\ x.bound /\ Holds(n, ep.author)
      BySelf == ep.commit \in A /\ Holds(n, ep.author)
  IN A # {} /\ e \in Sec(n) /\ (ByEntry \/ BySelf)
CoversAll(n, e) == \A h \in Departed(n) : Covers(n, e, h)
NeedRot(n) == \E e \in Current(n) : ~CoversAll(n, e)
HasCurrent(n) == Current(n) \cap Sec(n) # {}
MayEncrypt(n) == HasCurrent(n) /\ Newest(n) \in Sec(n) /\ ~NeedRot(n)

Holders(n) == {p \in Parties : Holds(n, p)}
NewEpoch(n, cid, author) ==
  [id |-> Len(eps), num |-> 1 + Ep(Newest(n)).num, commit |-> cid, author |-> author,
   lists |-> Current(n), hist |-> EstSet(n) \cap Sec(n)]

\* ---- actions ----------------------------------------------------------------
Deliver(n) == \E c \in cs : c.id \notin held[n] /\ held' = [held EXCEPT ![n] = @ \cup {c.id}]
              /\ UNCHANGED <<cs, eps, ents, boxes, adds, forged>>

\* rotating needs only the right to rotate (no current secret): the history box carries the
\* established secrets n holds
HonestRots == Cardinality({c \in cs : c.kind = "rot" /\ c.author \in Honest})
\* a rotator holds the role in its own view (one that does not makes no valid rotation; a box it
\* writes anyway carries only what it held, a stated limit)
Rotate(n) ==
  /\ NeedRot(n) /\ HonestRots < MaxE /\ Role(n, n) = ADMIN
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
\* Q's concurrent removal covers L's departure wherever S is held too (Dup; fails without Later:
\* only S is attributed there, so every node knowing both rotates again)
DupCovers == \A n \in Honest : \A e \in EpIds :
               (Ep(e).commit = "S2" /\ {"S", "S2"} \subseteq held[n] /\ e \in Sec(n) /\ Holds(n, "Q")) => Covers(n, e, "L")
\* Liveness is not modelled: a node holding everything covers all it knows by one rotation,
\* so the honest rotations are bounded by the departures and forgeries each node learns of
\* after the others' rotations; MaxE bounds them for the search.
================================================================================

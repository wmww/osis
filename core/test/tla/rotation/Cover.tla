-------------------------------- MODULE Cover --------------------------------
(* Which epochs cover a departure (spec/crypto.md §4 Names, Attributes,      *)
(* Covers). One actor, read role. First admin O and admin P are honest; L is *)
(* an admin that leaves by self-removal (S) and may forge: a history entry at *)
(* an epoch it holds listing S, a backdated rotation (valid: it was admin at  *)
(* that ts) listing S, or a rotation in S itself. With Audit, the audit-drop *)
(* shape: P demotes L to read (K), L self-removes (S), O removes P (D) and   *)
(* its audit drops K; admin Q may hold D without S and rotate for P.         *)
(* Rule "mark": any live entry counts; a departure made by an epoch's own    *)
(* rotation commit is covered unless that commit is a self-removal.          *)
(* Rule "author": only the entry the rotation commit wrote counts (bound by  *)
(* the keyset's names hash), and only while that commit's author holds the   *)
(* role; the same for a departure the rotation commit itself makes.          *)
(* Attr "any": a departure is attributed to the newest held commit that      *)
(* lowered the holder or whose audit dropped a write on its edge; "lowering":*)
(* to the newest at whose point the holder's grant for keys was lowered.     *)
(* Commits are delivered whole in any order; boxes are global (crypto is     *)
(* access: a party's secrets are the closure over boxes to it and history).  *)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS Rule, Attr, Forge, Audit, Writers, MaxE

Honest == Writers
Members == {"P", "L", "Q"}
Parties == {"O"} \cup Members
ADMIN == 2
READ == 1
NONE == 0

K == [id |-> "K", ts |-> 5, author |-> "P", h |-> "L", val |-> READ, kind |-> "chg"]
S == [id |-> "S", ts |-> 9, author |-> "L", h |-> "L", val |-> NONE, kind |-> "self"]
D == [id |-> "D", ts |-> 11, author |-> "O", h |-> "P", val |-> NONE, kind |-> "chg"]
Static == {S} \cup (IF Audit THEN {K, D} ELSE {})
StaticIds == {c.id : c \in Static}

VARIABLES cs,      \* edge and rotation commits that exist
          held,    \* held[n]: commit ids node n holds (L holds everything)
          eps,     \* epochs; eps[i + 1] has id i
          ents,    \* history entries: [e, author, names, bound]
          boxes,   \* {<<party, epoch id>>}
          adds,    \* history adds {<<epoch id, earlier epoch id>>}: an entry at e carries f
          wrote,   \* {<<epoch id, holders the writer saw departed>>}
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

Init0 == [edge |-> [h \in Members |-> ADMIN], low |-> {}, attr |-> [h \in Members |-> "none"]]

\* an explicit change applies by its author's admin (O always); a self-removal always
Applies(st, c) == c.kind = "self" \/ c.author = "O" \/ st.edge[c.author] = ADMIN
Step(st, c) ==
  LET ok == Applies(st, c)
      new == IF ok THEN [st.edge EXCEPT ![c.h] = c.val] ELSE st.edge
      lowered == ok /\ new[c.h] < st.edge[c.h]
  IN [edge |-> new,
      low |-> st.low \cup (IF lowered THEN {c.id} ELSE {}),
      attr |-> [h \in Members |-> IF lowered /\ h = c.h THEN c.id ELSE st.attr[h]]]

RECURSIVE WalkSeq(_, _)
WalkSeq(st, s) == IF s = <<>> THEN st ELSE WalkSeq(Step(st, Head(s)), Tail(s))
Edge(H) == {c \in cs : c.kind \in {"chg", "self"} /\ c.id \in H /\ ~Dropped(H, c)}
Walk(H) == WalkSeq(Init0, Sorted(Edge(H)))

\* a drop event: D held with a dropped write on the holder's edge (Attr "any")
DropsOn(H, h) == "D" \in H /\ \E c \in cs : c.id \in H /\ Dropped(H, c) /\ c.h = h
\* the name a node holding H attributes h's departure to
AttrOf(H, h) == LET W == Walk(H)
                    lowers == IF W.attr[h] = "none" THEN {} ELSE {W.attr[h]}
                    cands == lowers \cup (IF Attr = "any" /\ DropsOn(H, h) THEN {"D"} ELSE {})
                IN IF cands = {} THEN "none"
                   ELSE CHOOSE c \in cands : \A d \in cands : CommitOf(c).ts >= CommitOf(d).ts
\* the names a rotation by a node holding H writes
NamesOf(H) == Walk(H).low \cup (IF Attr = "any" /\ \E h \in Members : DropsOn(H, h) THEN {"D"} ELSE {})

\* ---- keys at a node ---------------------------------------------------------
RECURSIVE Close(_)
Close(X) == LET T == X \cup UNION {Ep(e).hist : e \in X} \cup {p[2] : p \in {q \in adds : q[1] \in X}}
            IN IF T = X THEN X ELSE Close(T)
Sec(p) == Close({e \in EpIds : <<p, e>> \in boxes})

Met(n, names) == names \subseteq held[n]
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
  LET a == AttrOf(held[n], h)
      ep == Ep(e)
      ByEntry == \E x \in ents : x.e = e /\ Met(n, x.names) /\ a \in x.names
                   /\ (Rule = "mark" \/ (x.bound /\ Holds(n, ep.author)))
      BySelf == a = ep.commit /\ (IF Rule = "mark" THEN ~ep.self ELSE Holds(n, ep.author))
  IN a # "none" /\ e \in Sec(n) /\ (ByEntry \/ BySelf)
CoversAll(n, e) == \A h \in Departed(n) : Covers(n, e, h)
NeedRot(n) == \E e \in Current(n) : ~CoversAll(n, e)
HasCurrent(n) == Current(n) \cap Sec(n) # {}
MayEncrypt(n) == HasCurrent(n) /\ Newest(n) \in Sec(n) /\ ~NeedRot(n)

Holders(n) == {p \in Parties : Holds(n, p)}
NewEpoch(n, cid, author, self) ==
  [id |-> Len(eps), num |-> 1 + Ep(Newest(n)).num, commit |-> cid, author |-> author,
   self |-> self, lists |-> Current(n), hist |-> EstSet(n) \cap Sec(n)]

\* ---- actions ----------------------------------------------------------------
Deliver(n) == \E c \in cs : c.id \notin held[n] /\ held' = [held EXCEPT ![n] = @ \cup {c.id}]
              /\ UNCHANGED <<cs, eps, ents, boxes, adds, forged>>

\* rotating needs only the right to rotate (no current secret): the history box carries the
\* established secrets n holds
HonestRots == Cardinality({c \in cs : c.kind = "rot" /\ c.author \in Honest})
Rotate(n) ==
  /\ NeedRot(n) /\ HonestRots < MaxE
  /\ LET id == "R" \o ToString(Len(eps))
         e == NewEpoch(n, id, n, FALSE)
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
  /\ LET e == NewEpoch("L", "B", "L", FALSE)
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
  /\ LET e == NewEpoch("L", "S", "L", TRUE)
     IN /\ eps' = Append(eps, e)
        /\ ents' = ents \cup {[e |-> e.id, author |-> "L", names |-> {}, bound |-> TRUE]}
        /\ boxes' = boxes \cup {<<p, e.id>> : p \in Holders("L") \cup {"L"}}
        /\ forged' = forged \cup {<<"selfrot", 0>>}
  /\ UNCHANGED <<cs, held, adds>>

WritesNow == {<<Newest(n), Departed(n)>> : n \in {m \in Honest : MayEncrypt(m)}}

E0 == [id |-> 0, num |-> 0, commit |-> "G", author |-> "O", self |-> FALSE, lists |-> {}, hist |-> {}]
Init == /\ cs = Static
        /\ held = [n \in Parties |-> IF n = "L" THEN StaticIds ELSE {}]
        /\ eps = <<E0>>
        /\ ents = {[e |-> 0, author |-> "O", names |-> {}, bound |-> TRUE]}
        /\ boxes = {<<p, 0>> : p \in Parties}
        /\ adds = {}
        /\ wrote = {}
        /\ forged = {}
Next == /\ \/ \E n \in Honest : Deliver(n) \/ Rotate(n) \/ HistAdd(n)
           \/ ForgeEntry \/ ForgeBackdated \/ SelfRot
        /\ wrote' = wrote \cup WritesNow
Spec == Init /\ [][Next]_vars

\* ---- properties -------------------------------------------------------------
TrulyDeparted == {h \in Members : Walk(AllIds).edge[h] = NONE}
\* content a writer wrote knowing a departure is never readable by the departed holder; what
\* hostile L holds it can hand any party out of band (its forgeries only automate that), so
\* another departed party reading an epoch L holds is no leak the rule judges
NoLeak == \A w \in wrote \cup WritesNow : \A m \in w[2] \cap TrulyDeparted :
            w[1] \notin Sec(m) \/ (m # "L" /\ w[1] \in Sec("L"))
\* Liveness is not modelled: a node holding everything covers all it knows by one rotation,
\* so the honest rotations are bounded by the departures and forgeries each node learns of
\* after the others' rotations; MaxE bounds them for the search.
================================================================================

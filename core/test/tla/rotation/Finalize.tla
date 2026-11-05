------------------------------- MODULE Finalize -------------------------------
(* Timed edges ended by a finalize, and the Met rule (spec/permissions.md §2  *)
(* Finalize, spec/crypto.md §4 Names, Met, Established; issues/finalize-noop- *)
(* unmet-lockout.md). One group, read role only. Writers (admins) set, renew, *)
(* finalize, rotate, re-seal and write; readers D1, D2 are passive holders.   *)
(* Edge writes are entries (spec/crdt.md §5.6): a change resets the entry its *)
(* author held live and puts a new one; a finalize resets the live entry of   *)
(* each ended edge (erase) and, saying keep, puts an `until` 0 entry. A reset *)
(* of an entry whose creation a node does not hold is unknown there. Each     *)
(* finalize carries a rotation naming the departures its author applied and  *)
(* its own departs mark. Delivery in any order, a commit whole; boxes (from   *)
(* rotations and re-seals) are global, so crypto is access: a party's secrets *)
(* are the closure over boxes to it and the history boxes of what it opens.   *)
(* Rule picks the Met rule:                                                    *)
(*   "old":     a name is met when its commit is held;                        *)
(*   "branch":  ... and each edge write it makes (as derived here) lowering a *)
(*              holder is applied;                                             *)
(*   "issue":   "old", and no re-seal of a holder into an epoch one of whose  *)
(*              names writes its edge: a node seeing one rotates instead;     *)
(*   "named":   a commit whose removal resets an unknown entry applies none  *)
(*              of its edge writes, and a name is met when its commit is held *)
(*              so resolved (a removal names the writes it ends);             *)
(*   "named_partial": as "named", but a commit's known writes apply alone.    *)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS Writers,     \* admins, honest unless Bogus (then "B" is hostile)
          Readers,     \* {"D1", "D2"}
          Finalizers,  \* honest writers that finalize
          WithU2,      \* D2 gets an `until` too, and A renews it before the finalizes
          Keep,        \* a finalize says keep (puts an `until` 0 entry)
          Bogus,       \* "B" holds a finalize of D1 also resetting an entry nobody holds
          Rule,
          MaxE,        \* bound on epochs, the initial one included
          MaxF         \* bound on honest finalizes

NONE == -1   \* no edge
INF == 1000  \* an edge without `until`
NOW == 6     \* every clock is past the `until`s (5) and before the renewal's (99)
Holderish(v) == v > 0
Ended(v, ts) == 0 < v /\ v < ts

\* Static edge commits: A's `until` writes and renewal, the hostile finalize.
U1 == [id |-> "U1", ts |-> 1, author |-> "A", kind |-> "chg",
       writes |-> {[h |-> "D1", reset |-> "G", val |-> 5, put |-> TRUE]}]
U2 == [id |-> "U2", ts |-> 2, author |-> "A", kind |-> "chg",
       writes |-> {[h |-> "D2", reset |-> "G", val |-> 5, put |-> TRUE]}]
R2 == [id |-> "R2", ts |-> 3, author |-> "A", kind |-> "chg",
       writes |-> {[h |-> "D2", reset |-> "U2", val |-> 99, put |-> TRUE]}]
FB == [id |-> "FB", ts |-> 6, author |-> "B", kind |-> "fin",
       writes |-> {[h |-> "D1", reset |-> "U1", val |-> NONE, put |-> FALSE],
                   [h |-> "D2", reset |-> "BOGUS", val |-> NONE, put |-> FALSE]}]
Static == {U1} \cup (IF WithU2 THEN {U2, R2} ELSE {}) \cup (IF Bogus THEN {FB} ELSE {})

E0 == [id |-> 0, num |-> 0, commit |-> "G", names |-> {}, departs |-> {}, lists |-> {}, hist |-> {}]
\* the hostile finalize's rotation: boxes the writers and D2, names nothing but itself
EB == [id |-> 1, num |-> 1, commit |-> "FB", names |-> {}, departs |-> {"FB"}, lists |-> {0}, hist |-> {0}]

Honest == IF Bogus THEN Writers \ {"B"} ELSE Writers

VARIABLES cs,     \* the commits that exist (edge commits and rotation commits)
          held,   \* held[n]: commit ids node n holds
          eps,    \* epochs, eps[i + 1] has id i
          boxes,  \* {<<party, epoch id>>}
          wrote,  \* {<<epoch id, holders the writer saw departed>>}: every
                  \* honest writer writes whenever it may (no branching)
          nfin,   \* honest finalizes made
          tl      \* tl[n]: the walk at n (a cache of Walk(held[n]))

vars == <<cs, held, eps, boxes, wrote, nfin, tl>>

Ep(i) == eps[i + 1]
EpIds == 0 .. Len(eps) - 1

\* ---- the role timeline at a node holding H ---------------------------------
KnownSet(H) == H \cup {"G"}
\* a removal (no edge left for keys) names the write it ends; a put of a live edge
\* sets the edge whatever it resets
Known(H, c) == \A w \in c.writes : Holderish(w.val) \/ w.reset \in KnownSet(H)
Whole == Rule = "named"
Ops(H, c) == IF Whole THEN (IF Known(H, c) THEN c.writes ELSE {})
             ELSE {w \in c.writes : w.reset \in KnownSet(H) \/ w.put}

RECURSIVE Sorted(_)
Sorted(S) == IF S = {} THEN <<>>
             ELSE LET m == CHOOSE c \in S : \A d \in S : c.ts <= d.ts
                  IN <<m>> \o Sorted(S \ {m})

Init0 == [edge |-> [h \in Readers |-> INF], src |-> [h \in Readers |-> "G"],
          attr |-> [h \in Readers |-> "none"], low |-> {}, noeff |-> {}]

Step(H, st, c) ==
  LET ops == Ops(H, c)
      opOn(h) == {w \in ops : w.h = h}
      applies(w) == c.kind = "chg" \/ Ended(st.edge[w.h], c.ts)
      new(h) == IF \E w \in opOn(h) : applies(w)
                THEN (CHOOSE w \in opOn(h) : TRUE).val ELSE st.edge[h]
      lowered == {h \in Readers : Holderish(st.edge[h]) /\ ~Holderish(new(h))}
      dud == \E w \in ops : Holderish(st.edge[w.h]) /\ ~Holderish(w.val) /\ ~applies(w)
  IN [edge |-> [h \in Readers |-> new(h)],
      src |-> [h \in Readers |-> IF \E w \in opOn(h) : applies(w) /\ w.put THEN c.id ELSE st.src[h]],
      attr |-> [h \in Readers |-> IF h \in lowered THEN c.id ELSE st.attr[h]],
      low |-> st.low \cup (IF lowered # {} THEN {c.id} ELSE {}),
      noeff |-> st.noeff \cup (IF dud THEN {c.id} ELSE {})]

RECURSIVE WalkSeq(_, _, _)
WalkSeq(H, st, s) == IF s = <<>> THEN st ELSE WalkSeq(H, Step(H, st, Head(s)), Tail(s))

WalkC(H, C) == WalkSeq(H, Init0, Sorted({c \in C : c.kind \in {"chg", "fin"} /\ c.id \in H}))
Walk(H) == WalkC(H, cs)
AllIds == {c.id : c \in cs}

\* ---- keys at a node -------------------------------------------------------
RECURSIVE Close(_)
Close(S) == LET T == S \cup UNION {Ep(e).hist : e \in S} IN IF T = S THEN S ELSE Close(T)
Sec(p) == Close({e \in EpIds : <<p, e>> \in boxes})

CommitOf(id) == CHOOSE c \in cs : c.id = id
Met(n, e) ==
  LET H == held[n]
      W == tl[n]
      ns == Ep(e).names \cup Ep(e).departs
  IN \A c \in ns : c \in H /\
       CASE Rule \in {"old", "issue"} -> TRUE
         [] Rule = "branch" -> c \notin W.noeff
         [] OTHER -> Known(H, CommitOf(c))

Est(n, e) == e = 0 \/ (Ep(e).commit \in held[n] /\ (e \in Sec(n) => Met(n, e)))
EstSet(n) == {e \in EpIds : Est(n, e)}
Current(n) == {e \in EstSet(n) : ~\E f \in EstSet(n) : e \in Ep(f).lists}
Newest(n) == CHOOSE e \in Current(n) : \A f \in Current(n) :
               Ep(e).num > Ep(f).num \/ (Ep(e).num = Ep(f).num /\ e <= f)

KeyHolders(n) == {h \in Readers : Holderish(tl[n].edge[h])}
Departed(n) == Readers \ KeyHolders(n)
Covers(n, e, h) == Met(n, e) /\ tl[n].attr[h] \in Ep(e).names \cup Ep(e).departs
CoversAll(n, e) == \A h \in Departed(n) : Covers(n, e, h)
NamesWrite(e, h) == \E c \in cs : c.id \in Ep(e).names \cup Ep(e).departs /\ \E w \in c.writes : w.h = h
Unboxed(n) == {<<h, e>> \in (KeyHolders(n) \cup Writers) \X Current(n) : <<h, e>> \notin boxes}
NeedRot(n) ==
  \/ \E e \in Current(n) : ~CoversAll(n, e)
  \/ Rule = "issue" /\ \E x \in Unboxed(n) : NamesWrite(x[2], x[1])
FinDue(n) == n \in Finalizers /\ \E h \in KeyHolders(n) : tl[n].edge[h] < NOW
HasCurrent(n) == Current(n) \cap Sec(n) # {}
MayEncrypt(n) == Newest(n) \in Sec(n) /\ ~FinDue(n) /\ ~NeedRot(n)

NewEpoch(n, cid, names, departs) ==
  [id |-> Len(eps), num |-> 1 + Ep(Newest(n)).num, commit |-> cid, names |-> names,
   departs |-> departs, lists |-> Current(n), hist |-> EstSet(n) \cap Sec(n)]

\* ---- actions --------------------------------------------------------------
Deliver(n) == \E c \in cs : c.id \notin held[n] /\ held' = [held EXCEPT ![n] = @ \cup {c.id}]
              /\ tl' = [tl EXCEPT ![n] = Walk(held'[n])]
              /\ UNCHANGED <<cs, eps, boxes, nfin>>

Finalize(n) ==
  /\ FinDue(n) /\ HasCurrent(n) /\ Len(eps) < MaxE /\ nfin < MaxF
  /\ LET W == tl[n]
         ended == {h \in KeyHolders(n) : W.edge[h] < NOW}
         id == "F" \o ToString(nfin)
         c == [id |-> id, ts |-> NOW + 1 + nfin, author |-> n, kind |-> "fin",
               writes |-> {[h |-> h, reset |-> W.src[h], val |-> IF Keep THEN 0 ELSE NONE, put |-> Keep] : h \in ended}]
         e == NewEpoch(n, id, W.low, {id})
     IN /\ cs' = cs \cup {c}
        /\ held' = [held EXCEPT ![n] = @ \cup {id}]
        /\ eps' = Append(eps, e)
        /\ boxes' = boxes \cup {<<p, e.id>> : p \in Writers \cup (KeyHolders(n) \ ended)}
        /\ nfin' = nfin + 1
        /\ tl' = [tl EXCEPT ![n] = WalkC(held'[n], cs')]

Rotate(n) ==
  /\ NeedRot(n) /\ ~FinDue(n) /\ HasCurrent(n) /\ Len(eps) < MaxE
  /\ LET id == "K" \o ToString(Len(eps))
         e == NewEpoch(n, id, tl[n].low, {})
     IN /\ cs' = cs \cup {[id |-> id, ts |-> 0, author |-> n, kind |-> "rot", writes |-> {}]}
        /\ held' = [held EXCEPT ![n] = @ \cup {id}]
        /\ eps' = Append(eps, e)
        /\ boxes' = boxes \cup {<<p, e.id>> : p \in Writers \cup KeyHolders(n)}
  /\ UNCHANGED <<nfin, tl>>

ResealOk(n, x) == x[2] \in Sec(n) /\ CoversAll(n, x[2]) /\ ~(Rule = "issue" /\ NamesWrite(x[2], x[1]))
Reseal(n) == /\ ~FinDue(n)
             /\ \E x \in Unboxed(n) : ResealOk(n, x)
             /\ boxes' = boxes \cup {x \in Unboxed(n) : ResealOk(n, x)}
             /\ UNCHANGED <<cs, held, eps, nfin, tl>>

WritesNow == {<<Newest(n), Departed(n)>> : n \in {m \in Honest : MayEncrypt(m)}}

Init == /\ cs = Static
        /\ held = [n \in Writers |-> IF n = "A" THEN {"U1", "U2", "R2"} \cap {c.id : c \in Static}
                                     ELSE IF n = "B" /\ Bogus THEN {"FB", "U1"} ELSE {}]
        /\ eps = IF Bogus THEN <<E0, EB>> ELSE <<E0>>
        /\ boxes = {<<p, 0>> : p \in Writers \cup Readers}
                   \cup (IF Bogus THEN {<<p, 1>> : p \in Writers \cup {"D2"}} ELSE {})
        /\ wrote = {}
        /\ nfin = 0
        /\ tl = [n \in Writers |-> Walk(held[n])]

Next == /\ \E n \in Honest : Deliver(n) \/ Finalize(n) \/ Rotate(n) \/ Reseal(n)
        /\ wrote' = wrote \cup WritesNow
Spec == Init /\ [][Next]_vars

\* ---- properties -----------------------------------------------------------
Full == Walk(AllIds)
TrulyDeparted == {h \in Readers : ~Holderish(Full.edge[h])}
\* No leak: content a writer wrote knowing a departure (the departure stands
\* with every commit held) is never readable by the departed holder.
NoLeak == \A w \in wrote \cup WritesNow : \A m \in w[2] \cap TrulyDeparted : w[1] \notin Sec(m)

\* Settles: once every commit is everywhere and no honest node has a key action
\* left, the honest writers agree on the current epochs (forks may stay, each
\* covering every departure) and may encrypt, and every holder holds each of
\* them (no lockout, no stranded renewed holder).
Busy(n) == \/ FinDue(n) /\ HasCurrent(n) /\ Len(eps) < MaxE /\ nfin < MaxF
           \/ NeedRot(n) /\ ~FinDue(n) /\ HasCurrent(n) /\ Len(eps) < MaxE
           \/ ~FinDue(n) /\ \E x \in Unboxed(n) : ResealOk(n, x)
Terminal == \A n \in Honest : held[n] = AllIds /\ ~Busy(n)
Good == \E c \in SUBSET EpIds :
          /\ \A n \in Honest : Current(n) = c /\ MayEncrypt(n)
          /\ \A p \in Honest \cup {h \in Readers : Holderish(Full.edge[h])} : c \subseteq Sec(p)
\* The finalize bound spent while one is still due is the model's limit, not a lockout.
BoundHit == nfin = MaxF /\ \E n \in Honest : FinDue(n)
Settles == Terminal /\ ~BoundHit => Good
================================================================================

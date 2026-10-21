------------------------------ MODULE Membership ------------------------------
(* The membership timeline and the tenure ledger (spec/permissions.md §1, §2,  *)
(* §5.1, §5.2, §6). A state is a history: a sequence of commits in generation  *)
(* order, each with a ts that may lie anywhere (clock skew, backdating) and a   *)
(* frontier taken from the commits generated before it. The invariants run     *)
(* the walk over the history and check its verdicts.                           *)
(* Things: actor A owned by key actor node 1; actor B owned by A. Edge members: *)
(* nodes, and B on A. Roles 0 none, 1 read, 2 write, 3 admin. Classes 0 none,  *)
(* 2 edge admin, 3 owner chain (attribution 1 = self-removal).                 *)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS NN,           \* nodes 1..NN; node 1 is the key actor owning A
          Scenario,     \* picks Genesis and Menu below
          MaxLen,       \* commits in a history, genesis included
          TsSet,        \* ts a free commit may take (even)
          SnapTs,       \* ts (odd) at which Neutral takes a roster snapshot
          SnapThings,   \* things Neutral snapshots ({} : none)
          SnapAu,       \* candidate authors of a snapshot of B (A: node 1)
          MaxDepth,     \* MAX_OWNER_DEPTH (A is 1 link below node 1, B 2)
          FrMode,       \* "all": a frontier is every commit received;
                        \* "subset": any subset of the commits generated before,
                        \* always with the author's chain certificates (Certs)
          SameKey,      \* nodes that may stamp two commits at one ts
          KeepStanding, \* FALSE: negative control, the demoter keeps nothing
          Chaos         \* TRUE: DropOrderFree explores every drop order

A == 101
B == 102
Things == {A, B}
Nodes == 1..NN
EdgeDom == ({B} \cup Nodes) \X Things
Depth(n) == IF n = A THEN 1 ELSE 2
DepthOK(n) == Depth(n) <= MaxDepth
Inf == 1000
NONE == <<-1, -1, -1>>
Absent == [r |-> 0, u |-> 0]
NoOpen == [r |-> 0, s |-> NONE]

Mx(a, b) == IF a > b THEN a ELSE b
Mn(a, b) == IF a < b THEN a ELSE b
MaxS(S) == IF S = {} THEN 0 ELSE CHOOSE m \in S : \A y \in S : y <= m

RECURSIVE LexLT(_, _, _)
LexLT(a, b, i) == IF i > Len(a) THEN FALSE
                  ELSE IF a[i] < b[i] THEN TRUE
                  ELSE IF a[i] > b[i] THEN FALSE
                  ELSE LexLT(a, b, i + 1)
Before(a, b) == LexLT(a, b, 1)
\* Keys (§6): <<ts, node, commit ID>>, a commit's ID its generation index.
KLT(a, b) == LexLT(a, b, 1)

(***************************************************************************)
(* Scenarios. A template is [kind, au, ops, tg]; an op is [tg, mb, r, u]    *)
(* (u = 0: no until). Genesis commits have fixed ts and full frontiers.    *)
(***************************************************************************)
Op(t, m, r, u) == [tg |-> t, mb |-> m, r |-> r, u |-> u]
E1(au, t, m, r, u) == [kind |-> "e", au |-> au, ops |-> <<Op(t, m, r, u)>>, tg |-> t]
E2(au, t, m1, m2) == [kind |-> "e", au |-> au, ops |-> <<Op(t, m1, 0, 0), Op(t, m2, 0, 0)>>, tg |-> t]
Cn(au, t) == [kind |-> "c", au |-> au, ops |-> <<>>, tg |-> t]
G(tpl, ts) == [tpl |-> tpl, ts |-> ts]

Genesis ==
  CASE Scenario = "core" -> <<G(E1(1, A, 2, 3, 0), 2), G(E1(1, A, 3, 3, 0), 4)>>
    [] Scenario = "group" -> <<G(E1(1, A, B, 3, 0), 2), G(E1(1, B, 2, 3, 0), 4)>>
    [] Scenario = "snapA" -> <<G(E1(1, A, 2, 3, 0), 2)>>
    [] Scenario = "snapB" -> <<G(E1(1, A, 2, 3, 0), 2)>>
    [] Scenario = "until" -> <<G(E1(1, A, 2, 3, 7), 2)>>
    [] Scenario = "samets" -> <<G(E1(1, A, 2, 3, 0), 2)>>
    [] Scenario = "multi" -> <<G(E1(1, A, B, 3, 0), 2), G(E1(1, B, 2, 3, 0), 4)>>
    [] Scenario = "depth" -> <<G(E1(1, A, 2, 3, 0), 2)>>
    [] Scenario = "sticky" -> <<G(E1(1, A, 2, 3, 0), 2), G(E1(1, A, 3, 3, 0), 4)>>
    [] Scenario = "forge" -> <<G(E1(1, A, 2, 3, 0), 2), G(E1(1, A, 3, 3, 0), 4)>>

Menu ==
  CASE Scenario = "core" ->
         <<E1(2, A, 3, 0, 0), E1(3, A, 2, 0, 0), E1(3, B, 3, 3, 0), E1(3, A, 2, 2, 0), Cn(3, B), Cn(3, A)>>
    [] Scenario = "group" ->
         <<E1(2, A, 3, 3, 0), E1(2, A, B, 0, 0), E1(1, A, B, 0, 0), E1(1, A, B, 3, 0), E1(1, B, 2, 0, 0), Cn(3, A)>>
    [] Scenario = "snapA" ->
         <<E1(2, B, 3, 3, 0), E1(2, A, 3, 2, 0), E1(1, A, 2, 0, 0), E1(2, A, 2, 2, 0), Cn(3, A), Cn(2, B)>>
    [] Scenario = "snapB" ->
         <<E1(2, B, 3, 2, 0), E1(2, B, 3, 0, 0), E1(1, A, 2, 0, 0), Cn(3, B), E1(3, B, 3, 0, 0)>>
    [] Scenario = "until" ->
         <<E1(1, A, 2, 0, 0), E1(2, B, 3, 3, 0), E1(1, A, 2, 3, 0), E1(2, A, 2, 2, 0), Cn(2, A), Cn(3, B)>>
    [] Scenario = "samets" ->
         <<E1(2, B, 3, 3, 0), E1(1, A, 2, 0, 0), E1(1, A, 2, 3, 0), Cn(2, A)>>
    [] Scenario = "multi" ->
         <<E2(2, A, B, 3), E1(2, A, 3, 3, 0), E1(2, A, B, 0, 0), E1(2, A, 3, 0, 0), Cn(3, A)>>
    [] Scenario = "depth" ->
         <<E1(2, B, 3, 3, 0), E1(1, A, 2, 0, 0), Cn(3, B), Cn(2, A), E1(2, A, 3, 3, 0)>>
    [] Scenario = "sticky" ->
         <<E1(3, B, 2, 3, 0), E1(2, A, 3, 0, 0), E1(1, A, 2, 0, 0), Cn(3, A)>>
    [] Scenario = "forge" ->
         <<E1(2, A, 3, 0, 0), E1(3, A, 2, 3, 9), E1(3, A, 2, 3, 0), Cn(3, A)>>

MkCommit(tpl, ts, fr, i) ==
  [kind |-> tpl.kind, id |-> i, gen |-> i, ts |-> ts, au |-> tpl.au,
   key5 |-> <<ts, tpl.au, i, 1, 0>>, ops |-> tpl.ops, tg |-> tpl.tg, fr |-> fr,
   ex |-> FALSE, ro |-> {}]

RECURSIVE GenHist(_)
GenHist(i) == IF i = 0 THEN <<>>
              ELSE LET h == GenHist(i - 1)
                   IN Append(h, MkCommit(Genesis[i].tpl, Genesis[i].ts,
                                         {c.id : c \in {h[j] : j \in 1..Len(h)}}, i))

VARIABLES hist, used
vars == <<hist, used>>

HSet == {hist[j] : j \in 1..Len(hist)}

Init == hist = GenHist(Len(Genesis)) /\ used = {}

\* Commits setting an edge of x or of B (over-approximating x's paths).
SetsFor(x) == {c \in HSet : c.kind = "e" /\ \E k \in 1..Len(c.ops) : c.ops[k].mb \in {x, B}}
\* An honest demoter holds its chain certificates (§4): the writes on its paths
\* and on its grantors' paths; its frontier lists them (§5.1).
Certs(au) == LET d1 == SetsFor(au)
             IN {c.id : c \in {c \in d1 \cup UNION {SetsFor(c2.au) : c2 \in d1} : c.au # au /\ c.au # 1}}
FrChoices(au) ==
  LET others == {c.id : c \in {c \in HSet : c.au # au /\ c.au # 1}}
  IN IF FrMode = "subset" THEN {S \cup Certs(au) : S \in SUBSET others} ELSE {others}

KeyFree(au, ts) == au \in SameKey \/ ~\E c \in HSet : c.au = au /\ c.ts = ts

Gen == /\ Len(hist) < MaxLen
       /\ \E i \in (1..Len(Menu)) \ used, ts \in TsSet :
            LET tpl == Menu[i] IN
            /\ KeyFree(tpl.au, ts)
            /\ \E fr \in (IF tpl.kind = "e" THEN FrChoices(tpl.au) ELSE {{}}) :
                 /\ hist' = Append(hist, MkCommit(tpl, ts, fr, Len(hist) + 1))
                 /\ used' = used \cup {i}

Next == Gen
Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Roles and classes (§1). Paths climb alive edges and owner links: node 1  *)
(* owns A, A owns B, B may be a member of A (so admin of B can reach A).    *)
(***************************************************************************)
AR(E, p, t) == IF E[p].r > 0 /\ (E[p].u = 0 \/ t < E[p].u) THEN E[p].r ELSE 0
Alive(v, t) == v.r > 0 /\ (v.u = 0 \/ t < v.u)

Roles(E, t) ==
  [x \in Nodes |->
     LET a0 == Mx(IF x = 1 THEN 3 ELSE 0, AR(E, <<x, A>>, t))
         dB == AR(E, <<x, B>>, t)
         rA == Mx(a0, Mn(Mx(dB, a0), AR(E, <<B, A>>, t)))
     IN [a |-> rA, b |-> Mx(dB, rA)]]
RoleOn(R, x, n) == IF n = A THEN R[x].a ELSE R[x].b
\* owner chain: the key actor at the top, or admin of an actor above n
Class(R, x, n) ==
  IF n = A THEN (IF x = 1 THEN 3 ELSE IF R[x].a = 3 THEN 2 ELSE 0)
  ELSE (IF x = 1 \/ R[x].a = 3 THEN 3 ELSE IF R[x].b = 3 THEN 2 ELSE 0)
Reaches(R, x, m) == x = m \/ (m = B /\ R[x].b >= 1)

UntilLE(a, b) == b = 0 \/ (a # 0 /\ a <= b)
Lowers(nv, old, t) ==
  Alive(old, t) /\ (nv.r = 0 \/ (nv.r <= old.r /\ UntilLE(nv.u, old.u) /\ nv # old))
\* §6 "audits": the edge as restored exceeds the new value
Exceeds(r, nv, t) == r > 0 /\ (~Alive(nv, t) \/ nv.r < r \/ nv.u # 0)
Norm(v, t) == IF v.r = 0 \/ (v.u # 0 /\ v.u <= t) THEN Absent ELSE v

(***************************************************************************)
(* The walk (§5.1).                                                         *)
(***************************************************************************)
Key0 == <<0, 0, 0, 0, 0>>
St0(E0, D) ==
  [E |-> E0, P |-> [p \in EdgeDom |-> 0], K |-> [p \in EdgeDom |-> [x \in Nodes |-> 0]],
   S |-> [p \in EdgeDom |-> 0], D |-> D,
   app |-> {}, dem |-> {}, fall |-> {}, ex |-> {}, chg |-> <<>>, cinfo |-> {},
   grow |-> {}, drec |-> {}, cands |-> <<>>, rej |-> FALSE,
   everW |-> {q \in Nodes \X Things : DepthOK(q[2]) /\ RoleOn(Roles(E0, 0), q[1], q[2]) >= 2},
   lastW |-> [q \in Nodes \X Things |-> Key0]]

UpdW(st, key, t) ==
  LET R == Roles(st.E, t)
      w == {q \in Nodes \X Things : DepthOK(q[2]) /\ RoleOn(R, q[1], q[2]) >= 2}
  IN [st EXCEPT !.everW = @ \cup w,
                !.lastW = [q \in Nodes \X Things |-> IF q \in w THEN key ELSE @[q]]]

\* Sets edge e to nv. explicit: audits as §5.1 step 4 by node au with
\* frontier fr; besides fr only the commit cid counts as covered (the
\* demoter's chain writes too, §5.1 Frontier).
Change(st, e, nv, t, key, au, explicit, fr, cid, gen) ==
  LET old == st.E[e]
      ck == <<key[1], key[2], key[3]>>
  IN
  IF ~explicit THEN
    [st EXCEPT !.E[e] = nv, !.P[e] = Mx(@, old.r), !.S[e] = cid,
       !.chg = Append(@, [m |-> e[1], t |-> e[2], key |-> ck, nv |-> nv, ex |-> FALSE,
                          aud |-> 0, fr |-> {}])]
  ELSE
    LET base == Mx(st.P[e], old.r)
        kept == st.K[e]
        rAll == Mx(base, MaxS({kept[x] : x \in Nodes}))
        lowered == Exceeds(rAll, nv, t)
        Rb == Roles(st.E, t)
        reach == {x \in Nodes : Reaches(Rb, x, e[1])}
        E1x == [st.E EXCEPT ![e] = nv]
        R1 == Roles(E1x, t)
        xs == IF lowered THEN {x \in reach \ {au} : Mx(base, kept[x]) > 0} ELSE {}
        RB == [x \in xs |-> Roles([st.E EXCEPT ![e] = [r |-> Mx(base, kept[x]), u |-> 0]], t)]
        pairs == {[x |-> x, n |-> n, cb |-> Class(RB[x], x, n), ca |-> Class(R1, x, n),
                   rb |-> RoleOn(RB[x], x, n), ra |-> RoleOn(R1, x, n)] : x \in xs, n \in Things}
        falls == {[x |-> q.x, n |-> q.n, cb |-> q.cb, ca |-> q.ca, key |-> key, cid |-> cid,
                   gen |-> gen, au |-> au, m |-> e[1], t |-> e[2]] : q \in {q \in pairs : q.ca < q.cb}}
        dems == {[x |-> q.x, n |-> q.n, key |-> key, fr |-> fr, cid |-> cid, gen |-> gen]
                   : q \in {q \in pairs : q.rb >= 2 /\ q.ra < 2}}
        drops == {a \in st.app : a.attr >= 2 /\ a.cid \notin fr /\ a.cid # cid
                    /\ \E f \in falls : f.x = a.au /\ f.n = a.tg /\ f.ca < a.attr /\ a.attr <= f.cb}
        own == au \in reach /\ base > 0
        K1 == [x \in Nodes |-> IF KeepStanding /\ own /\ x = au THEN Mx(base, kept[au]) ELSE 0]
    IN [st EXCEPT !.E = E1x, !.P[e] = 0, !.K[e] = K1, !.S[e] = cid,
          !.fall = @ \cup falls, !.dem = @ \cup dems,
          !.grow = @ \cup {a.w : a \in drops},
          !.drec = @ \cup {[w |-> a.w, au |-> a.au, attr |-> a.attr, tg |-> a.tg, byau |-> au,
                             bycid |-> cid] : a \in drops},
          !.chg = Append(@, [m |-> e[1], t |-> e[2], key |-> ck, nv |-> nv, ex |-> TRUE,
                             aud |-> IF lowered THEN rAll ELSE 0, fr |-> fr]),
          !.ex = @ \cup {[cid |-> cid, au |-> au, m |-> e[1], t |-> e[2], key |-> key, gen |-> gen,
                          fr |-> fr, nv |-> nv, reach |-> reach,
                          reachAdmin |-> {x \in Nodes : x = e[1] \/ (e[1] = B /\ Rb[x].b = 3)},
                          after |-> [x \in Nodes |-> Class(R1, x, e[2])],
                          was |-> Mx(base, kept[au]), auReach |-> au \in reach]}]

\* §5.1 step 2 and §2: -1 not applied, 1 self-removal, 2/3 by class.
Judge(st, R, c, k) ==
  LET o == c.ops[k]
      e == <<o.mb, o.tg>>
      nv == Norm([r |-> o.r, u |-> o.u], c.ts)
      cls == Class(R, c.au, o.tg)
  IN IF o.mb = o.tg \/ (o.tg = A /\ o.mb = 1) \/ ~DepthOK(o.tg) \/ <<c.id, k>> \in st.D THEN -1
     ELSE IF Lowers(nv, st.E[e], c.ts)
             /\ (o.mb = c.au \/ (o.mb \in Things /\ RoleOn(R, c.au, o.mb) = 3 /\ cls < 2)) THEN 1
     ELSE IF cls >= 2 THEN cls ELSE -1

RECURSIVE ApplyOps(_, _, _, _, _)
ApplyOps(st, c, js, k, t) ==
  IF k > Len(c.ops) THEN st
  ELSE IF js[k] = -1 THEN ApplyOps(st, c, js, k + 1, t)
  ELSE LET o == c.ops[k]
           e == <<o.mb, o.tg>>
           nv == Norm([r |-> o.r, u |-> o.u], t)
           rec == [w |-> <<c.id, k>>, cid |-> c.id, au |-> c.au, tg |-> o.tg, attr |-> js[k],
                   key |-> c.key5, gen |-> c.gen]
           st1 == [st EXCEPT !.app = @ \cup {rec}]
       IN ApplyOps(Change(st1, e, nv, t, c.key5, c.au, js[k] >= 2, c.fr, c.id, c.gen),
                   c, js, k + 1, t)

RECURSIVE ApplyRo(_, _, _, _, _)
ApplyRo(st, ev, ms, i, t) ==
  IF i > Len(ms) THEN st
  ELSE LET p == <<ms[i], ev.tg>>
           q == {x \in ev.ro : x.m = ms[i]}
           v == IF q = {} THEN Absent ELSE (CHOOSE x \in q : TRUE).v
       IN ApplyRo(IF st.E[p] = v THEN st ELSE Change(st, p, v, t, ev.key5, ev.au, FALSE, {}, ev.id, 0),
                  ev, ms, i + 1, t)
MemSeq(n) == IF n = A THEN <<B>> \o [i \in 1..NN - 1 |-> i + 1] ELSE [i \in 1..NN |-> i]

Step(ev, st) ==
  LET t == ev.ts
      R == Roles(st.E, t)
  IN
  CASE ev.kind = "e" ->
         LET js == [k \in 1..Len(ev.ops) |-> Judge(st, R, ev, k)]
         IN UpdW(ApplyOps(st, ev, js, 1, t), ev.key5, t)
    [] ev.kind = "c" ->
         LET ra == IF DepthOK(ev.tg) THEN RoleOn(R, ev.au, ev.tg) ELSE 0
         IN [st EXCEPT !.cinfo = @ \cup {[cid |-> ev.id, au |-> ev.au, tg |-> ev.tg, key |-> ev.key5,
                gen |-> ev.gen, roleAt |-> ra, cls |-> Class(R, ev.au, ev.tg),
                ever |-> <<ev.au, ev.tg>> \in st.everW \/ ra >= 2]}]
    [] ev.kind = "v" ->
         LET o == ev.ops[1]
         IN UpdW(Change(st, <<o.mb, o.tg>>, [r |-> o.r, u |-> o.u], t, ev.key5, ev.au, ev.ex,
                        ev.fr, 0, 0), ev.key5, t)
    [] ev.kind = "s" ->
         IF Class(R, ev.au, ev.tg) < 3 \/ <<ev.id, 1>> \in st.D THEN [st EXCEPT !.rej = TRUE]
         ELSE LET st1 == [st EXCEPT !.app = @ \cup {[w |-> <<ev.id, 1>>, cid |-> ev.id, au |-> ev.au,
                            tg |-> ev.tg, attr |-> 3, key |-> ev.key5, gen |-> ev.gen]}]
              IN UpdW(ApplyRo(st1, ev, MemSeq(ev.tg), 1, t), ev.key5, t)

\* One walk. stop: restart at the first write that adds to D (the spec);
\* else record each such write's additions in cands and go on.
RECURSIVE Pass(_, _, _, _)
Pass(evs, i, st, stop) ==
  IF i > Len(evs) \/ st.rej THEN st
  ELSE LET s2 == Step(evs[i], st)
       IN IF s2.grow = {} THEN Pass(evs, i + 1, s2, stop)
          ELSE IF stop THEN s2
          ELSE Pass(evs, i + 1, [s2 EXCEPT !.cands = Append(@, s2.grow), !.grow = {}], stop)

\* §5.1 step 5: walk until a walk adds nothing to D. drecAll: every drop.
RECURSIVE WalkD(_, _, _, _)
WalkD(evs, E0, D, acc) ==
  LET p == Pass(evs, 1, St0(E0, D), TRUE)
  IN IF p.rej \/ p.grow = {} THEN [p EXCEPT !.drec = acc \cup @]
     ELSE WalkD(evs, E0, D \cup p.grow, acc \cup p.drec)

LTev(a, b) == Before(a.key5, b.key5)
Evs(h) == SortSeq(h, LTev)
E00 == [p \in EdgeDom |-> Absent]
W0 == WalkD(Evs(hist), E00, {}, {})

(***************************************************************************)
(* Layer 2 (§5.2): content validity of a content commit c.                  *)
(***************************************************************************)
RoleEnd(W, x, n) == RoleOn(Roles(W.E, Inf), x, n)
Newest(ds) == CHOOSE d \in ds : \A d2 \in ds : ~Before(d.key, d2.key)
CValid(W, c) ==
  LET ds == {d \in W.dem : d.x = c.au /\ d.n = c.tg}
  IN /\ DepthOK(c.tg)
     /\ \/ RoleEnd(W, c.au, c.tg) >= 2 /\ c.ever
        \/ c.roleAt >= 2 /\ ~\E d \in ds : Before(c.key, d.key)
        \/ ds # {} /\ c.cid \in Newest(ds).fr

Verd(W) == [edges |-> {a.w : a \in W.app},
            content |-> {c.cid : c \in {c \in W.cinfo : CValid(W, c)}},
            roles |-> [q \in Nodes \X Things |-> RoleEnd(W, q[1], q[2])]]

(***************************************************************************)
(* Roster snapshot production (§6) from walk W, for thing N at key sk.     *)
(***************************************************************************)
RECURSIVE Led(_, _, _, _, _, _, _)
Led(chs, i, m, cur, open, ents, setKey) ==
  IF i > Len(chs) THEN [ents |-> ents, cur |-> cur, open |-> open, setKey |-> setKey]
  ELSE LET ch == chs[i] IN
  IF ch.m # m THEN Led(chs, i + 1, m, cur, open, ents, setKey)
  ELSE
    LET t == ch.key[1]
        exp == cur.u # 0 /\ cur.u <= t /\ open.r > 0
        ents1 == IF exp THEN ents \cup {[m |-> m, r |-> open.r, s |-> open.s, u |-> <<cur.u, 0, 0>>,
                                         hf |-> FALSE, fr |-> {}]} ELSE ents
        open1 == IF exp THEN NoOpen ELSE open
        newR == IF Alive(ch.nv, t) /\ ch.nv.r >= 2 THEN ch.nv.r ELSE 0
        aud == ch.aud >= 2
        split == ch.aud > 0 /\ open1.r > 0 /\ open1.r < ch.aud
        ends == open1.r # newR \/ split
        ents2 == IF ends /\ open1.r > 0
                 THEN ents1 \cup {[m |-> m, r |-> open1.r, s |-> open1.s, u |-> ch.key,
                                   hf |-> aud, fr |-> IF aud THEN ch.fr ELSE {}]}
                 ELSE ents1
        open2 == IF ends THEN (IF newR >= 2 THEN [r |-> newR, s |-> ch.key] ELSE NoOpen) ELSE open1
        ents3 == IF aud /\ open1.r = 0
                 THEN ents2 \cup {[m |-> m, r |-> ch.aud, s |-> ch.key, u |-> ch.key, hf |-> TRUE, fr |-> ch.fr]}
                 ELSE ents2
    IN Led(chs, i + 1, m, ch.nv, open2, ents3, ch.key)

Production(W, N, sk) ==
  LET chs == SelectSeq(W.chg, LAMBDA ch : ch.t = N /\ KLT(ch.key, sk))
      ms == {MemSeq(N)[i] : i \in 1..Len(MemSeq(N))}
      per == [m \in ms |-> Led(chs, 1, m, Absent, NoOpen, {}, NONE)]
  IN [ledger |-> UNION {per[m].ents : m \in ms},
      roster |-> {[m |-> m, v |-> per[m].cur,
                   s |-> IF per[m].cur.r >= 2
                         THEN (IF per[m].open.r > 0 THEN per[m].open.s ELSE per[m].setKey)
                         ELSE NONE] : m \in {m \in ms : per[m].cur # Absent}}]

(***************************************************************************)
(* Replay (§6 epoch start): N's edges before S as virtual writes at their   *)
(* keys, an entry with a frontier an explicit demotion by its key's node.  *)
(***************************************************************************)
RECURSIVE SortKeys(_)
SortKeys(S) == IF S = {} THEN <<>>
               ELSE LET k == CHOOSE k \in S : \A y \in S : ~KLT(y, k)
                    IN <<k>> \o SortKeys(S \ {k})

ValueAt(Lm, ro, b, wr) ==
  LET inside == {e.r : e \in {e \in Lm : b # NONE /\ ~KLT(b, e.s) /\ KLT(b, e.u)}}
  IN IF inside # {} THEN [r |-> MaxS(inside), u |-> 0]
     ELSE IF \E q \in ro : /\ (wr \/ (q.s # NONE /\ q.s = b))
                           /\ (q.s = NONE \/ (b # NONE /\ ~KLT(b, q.s)))
                           /\ \A e \in Lm : b # NONE /\ ~KLT(b, e.u)
          THEN (CHOOSE q \in ro : TRUE).v ELSE Absent

VEv(N, m, b, j, v, ex, fr) ==
  [kind |-> "v", id |-> j, gen |-> 0, ts |-> b[1], au |-> b[2], key5 |-> <<b[1], b[2], b[3], j - 2, m>>,
   ops |-> <<Op(N, m, v.r, v.u)>>, tg |-> N, fr |-> fr, ex |-> ex, ro |-> {}]

RECURSIVE VFold(_, _, _, _, _, _, _, _)
VFold(N, m, Lm, ro, ks, i, prev, out) ==
  IF i > Len(ks) THEN out
  ELSE LET b == ks[i]
           fe == {e \in Lm : e.u = b /\ e.hf}
           v1 == ValueAt(Lm, ro, b, FALSE)
           out1 == IF fe # {} THEN Append(out, VEv(N, m, b, 0, v1, TRUE, (CHOOSE e \in fe : TRUE).fr)) ELSE out
           prev1 == IF fe # {} THEN v1 ELSE prev
           v2 == ValueAt(Lm, ro, b, TRUE)
           out2 == IF v2 # prev1 THEN Append(out1, VEv(N, m, b, 1, v2, FALSE, {})) ELSE out1
       IN VFold(N, m, Lm, ro, ks, i + 1, v2, out2)

Virtuals(N, P, sk) ==
  LET ms == {MemSeq(N)[i] : i \in 1..Len(MemSeq(N))}
      Lm(m) == {e \in P.ledger : e.m = m}
      ro(m) == {q \in P.roster : q.m = m}
      ks(m) == SortKeys({k \in ({e.s : e \in Lm(m)} \cup {e.u : e \in Lm(m)} \cup {q.s : q \in ro(m)}) \ {NONE}
                         : KLT(k, sk)})
      seqs == [m \in ms |-> VFold(N, m, Lm(m), ro(m), ks(m), 1, ValueAt(Lm(m), ro(m), NONE, TRUE), <<>>)]
      E0 == [p \in EdgeDom |-> IF p[2] = N /\ p[1] \in ms THEN ValueAt(Lm(p[1]), ro(p[1]), NONE, TRUE)
                               ELSE Absent]
  IN [evs |-> UNION {{seqs[m][i] : i \in 1..Len(seqs[m])} : m \in ms}, E0 |-> E0]

RECURSIVE SetToSeq(_)
SetToSeq(S) == IF S = {} THEN <<>> ELSE LET x == CHOOSE x \in S : TRUE IN <<x>> \o SetToSeq(S \ {x})
\* The walk of hist with a roster snapshot of N by au at ts s, produced from W0.
WithSnap(N, s, au) ==
  LET sk == <<s, au, 99>>
      sk5 == <<s, au, 99, 1, 0>>
      P == Production(W0, N, sk)
      V == Virtuals(N, P, sk)
      S == [kind |-> "s", id |-> 99, gen |-> 99, ts |-> s, au |-> au, key5 |-> sk5, ops |-> <<>>,
            tg |-> N, fr |-> {}, ex |-> FALSE, ro |-> {q \in P.roster : TRUE}]
      kept == {c \in HSet : ~(c.kind = "e" /\ c.tg = N /\ Before(c.key5, sk5))}
      evs == SortSeq(SetToSeq(kept \cup V.evs \cup {S}), LTev)
  IN [w |-> WalkD(evs, V.E0, {}, {}), kept |-> kept, P |-> P]

(***************************************************************************)
(* Properties.                                                              *)
(***************************************************************************)
TypeOK == /\ Len(hist) <= MaxLen
          /\ \A c \in HSet : c.ts \in Nat

\* (2) Neutrality: a roster snapshot of N taken at any point, with the roster
\* and ledger the timeline computes, changes no verdict (§6).
NeutralAt(N, s, au) ==
  LET X == WithSnap(N, s, au)
      cmp == {<<c.id, k>> : c \in {c \in X.kept : c.kind = "e"}, k \in 1..2}
      V0 == Verd(W0)
      V1 == Verd(X.w)
  IN X.w.rej \/ (V0.edges \cap cmp = V1.edges \cap cmp /\ V0.content = V1.content /\ V0.roles = V1.roles)
Neutral == \A N \in SnapThings, s \in SnapTs :
             \A au \in (IF N = A THEN {1} ELSE SnapAu) : NeutralAt(N, s, au)

\* (1) Determinism: the verdicts do not depend on the order in which drops are
\* found (every write that adds to D may be taken first).
RECURSIVE WalkAll(_, _, _)
WalkAll(evs, E0, D) ==
  LET p == Pass(evs, 1, St0(E0, D), FALSE)
  IN IF p.cands = <<>> THEN {Verd(p)}
     ELSE UNION {WalkAll(evs, E0, D \cup p.cands[j]) : j \in 1..Len(p.cands)}
DropOrderFree == Chaos => WalkAll(Evs(hist), E00, {}) = {Verd(W0)}

\* (3) A member whose class (or role) a valid explicit demotion R took away:
\* its edge writes generated after R and ordered before R are dropped; its
\* content generated after its newest demotion, with no regain, is invalid.
LateEdge == \A f \in W0.fall : \A a \in W0.app :
              (a.au = f.x /\ a.tg = f.n /\ a.attr >= 2 /\ f.ca < a.attr /\ a.attr <= f.cb /\ a.gen > f.gen)
                => Before(f.key, a.key)
LateContent == \A c \in W0.cinfo :
  LET ds == {d \in W0.dem : d.x = c.au /\ d.n = c.tg}
  IN (ds # {} /\ c.gen > Newest(ds).gen /\ ~Before(Newest(ds).key, W0.lastW[<<c.au, c.tg>>])
      /\ RoleEnd(W0, c.au, c.tg) < 2) => ~CValid(W0, c)

\* (4) A demotion never drops its author's writes; a demoter that reached the
\* member keeps its standing until the next explicit write on that edge,
\* which audits it.
NoSelfDrop == \A r \in W0.drec : r.au # r.byau
StandingAudited ==
  \A r1, r2 \in W0.ex :
    ( /\ r1.m = B /\ r2.m = B /\ r1.t = r2.t /\ Before(r1.key, r2.key) /\ r1.au # r2.au
      /\ r1.cid # 0 /\ r2.cid # 0 /\ r1.auReach /\ r1.was = 3 /\ r2.nv = Absent
      /\ r1.au \in r2.reachAdmin /\ r2.after[r1.au] < 2
      /\ ~\E r3 \in W0.ex : r3.m = B /\ r3.t = r1.t /\ Before(r1.key, r3.key) /\ Before(r3.key, r2.key) )
    => ~\E a \in W0.app : a.au = r1.au /\ a.tg = r1.t /\ a.attr = 2 /\ Before(a.key, r1.key)
                           /\ a.cid \notin r2.fr

\* (5) Owner chain: chain authority confers write wherever the chain reaches
\* (content by a chain node stands unless a later demotion); nothing on a thing
\* beyond MAX_OWNER_DEPTH is valid.
ChainContent == \A c \in W0.cinfo :
  (DepthOK(c.tg) /\ c.cls = 3 /\ ~\E d \in W0.dem : d.x = c.au /\ d.n = c.tg /\ Before(c.key, d.key))
    => CValid(W0, c)
DepthCap == \A n \in Things : ~DepthOK(n) =>
  /\ \A a \in W0.app : a.tg # n
  /\ \A c \in W0.cinfo : c.tg = n => ~CValid(W0, c)

\* Probes (expected to fail; they show the instances reach the cases checked).
ProbeNoDrop == W0.drec = {}
ProbeNoDem == W0.dem = {}
ProbeNoKept == ~\E r \in W0.ex : r.auReach /\ r.was = 3 /\ r.m = B
ProbeNoInvalidContent == \A c \in W0.cinfo : CValid(W0, c)
ProbeNoRestart == Cardinality(WalkAll(Evs(hist), E00, {})) = 1 /\ Len(Pass(Evs(hist), 1, St0(E00, {}), FALSE).cands) <= 1
ProbeNoLedger == \A N \in SnapThings, s \in SnapTs : Production(W0, N, <<s, 1, 99>>).ledger = {}
ProbeNoLedgerFr == \A N \in SnapThings, s \in SnapTs : \A e \in Production(W0, N, <<s, 1, 99>>).ledger : ~e.hf
ProbeSnapRejected == \A N \in SnapThings, s \in SnapTs :
  \A au \in (IF N = A THEN {1} ELSE SnapAu) : WithSnap(N, s, au).w.rej
\* a snapshot that applies while an earlier tenure's frontier drops a write on B
ProbeLedgerDrops == \A N \in SnapThings, s \in SnapTs :
  \A au \in (IF N = A THEN {1} ELSE SnapAu) :
    LET X == WithSnap(N, s, au) IN X.w.rej \/ ~\E r \in X.w.drec : r.bycid = 0
ProbeNoAuditOnly ==\A N \in SnapThings, s \in SnapTs : \A e \in Production(W0, N, <<s, 1, 99>>).ledger : e.s # e.u

=============================================================================

-------------------------------- MODULE Roles ---------------------------------
(* The role timeline (spec/permissions.md §1, §2, §5.1, §5.2). A state is a  *)
(* history: a sequence of commits in generation order, each with a ts that   *)
(* may lie anywhere (clock skew, backdating) and a frontier taken from the    *)
(* commits generated before it. The invariants run the walk over the history *)
(* and check its verdicts.                                                    *)
(* Things: actor A owned by key actor node 1; actor B owned by A. Edge holders: *)
(* nodes, and B on A. Roles 0 none, 1 read, 2 write, 3 admin. Classes 0 none,  *)
(* 2 edge admin, 3 owner chain; a write is audited by its author's class on   *)
(* `on`: its target, or for a self-removal through B, B.                      *)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS NN,           \* nodes 1..NN; node 1 is the key actor owning A
          Scenario,     \* picks Genesis and Menu below
          MaxLen,       \* commits in a history, genesis included
          TsSet,        \* ts a free commit may take (even)
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
Absent == [r |-> 0, u |-> 0]

Mx(a, b) == IF a > b THEN a ELSE b
Mn(a, b) == IF a < b THEN a ELSE b
MaxS(S) == IF S = {} THEN 0 ELSE CHOOSE m \in S : \A y \in S : y <= m

RECURSIVE LexLT(_, _, _)
LexLT(a, b, i) == IF i > Len(a) THEN FALSE
                  ELSE IF a[i] < b[i] THEN TRUE
                  ELSE IF a[i] > b[i] THEN FALSE
                  ELSE LexLT(a, b, i + 1)
\* Keys (§5.1): <<ts, node, commit ID>>, a commit's ID its generation index.
Before(a, b) == LexLT(a, b, 1)

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
    [] Scenario = "group" -> <<G(E1(1, A, B, 3, 0), 2), G(E1(1, B, 2, 3, 0), 4), G(E1(1, A, 2, 3, 9), 5)>>
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
   key |-> <<ts, tpl.au, i>>, ops |-> tpl.ops, tg |-> tpl.tg, fr |-> fr]

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
(* owns A, A owns B, B may be a holder of A (so admin of B can reach A).    *)
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
\* The write lowers the edge as restored (role r): removes it, lowers the role
\* or gives it an `until`.
Exceeds(r, nv, t) == r > 0 /\ (~Alive(nv, t) \/ nv.r < r \/ nv.u # 0)
Norm(v, t) == IF v.r = 0 \/ (v.u # 0 /\ v.u <= t) THEN Absent ELSE v

(***************************************************************************)
(* The walk (§5.1).                                                         *)
(***************************************************************************)
Key0 == <<0, 0, 0>>
\* No edges before the history (its genesis commits set them).
E00 == [p \in EdgeDom |-> Absent]
St0(D) ==
  [E |-> E00, P |-> [p \in EdgeDom |-> 0], K |-> [p \in EdgeDom |-> [x \in Nodes |-> 0]],
   D |-> D, app |-> {}, dem |-> {}, fall |-> {}, ex |-> {}, cinfo |-> {},
   grow |-> {}, drec |-> {}, cands |-> <<>>,
   everW |-> {q \in Nodes \X Things : DepthOK(q[2]) /\ RoleOn(Roles(E00, 0), q[1], q[2]) >= 2},
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
  IN
  IF ~explicit THEN [st EXCEPT !.E[e] = nv, !.P[e] = Mx(@, old.r)]
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
                    /\ \E f \in falls : f.x = a.au /\ f.n = a.on /\ f.ca < a.attr /\ a.attr <= f.cb}
        own == au \in reach /\ base > 0
        K1 == [x \in Nodes |-> IF KeepStanding /\ own /\ x = au THEN Mx(base, kept[au]) ELSE 0]
    IN [st EXCEPT !.E = E1x, !.P[e] = 0, !.K[e] = K1,
          !.fall = @ \cup falls, !.dem = @ \cup dems,
          !.grow = @ \cup {a.w : a \in drops},
          !.drec = @ \cup {[w |-> a.w, au |-> a.au, attr |-> a.attr, tg |-> a.tg, byau |-> au]
                            : a \in drops},
          !.ex = @ \cup {[cid |-> cid, au |-> au, m |-> e[1], t |-> e[2], key |-> key, gen |-> gen,
                          fr |-> fr, nv |-> nv, reach |-> reach,
                          reachAdmin |-> {x \in Nodes : x = e[1] \/ (e[1] = B /\ Rb[x].b = 3)},
                          after |-> [x \in Nodes |-> Class(R1, x, e[2])],
                          was |-> Mx(base, kept[au]), auReach |-> au \in reach]}]

\* §5.1 step 2 and §2: a = -1 not applied, else the class attributed (on `on`);
\* s: a self-removal (audits nothing), attributed to the author's class on the
\* holder it is admin of, or on the target for its own edge. Through a holder,
\* the author's class on the target is taken with that edge disregarded
\* (authority through the holder does not count).
Judge(st, R, c, k) ==
  LET o == c.ops[k]
      e == <<o.mb, o.tg>>
      nv == Norm([r |-> o.r, u |-> o.u], c.ts)
      cls == Class(R, c.au, o.tg)
      clsWithout == Class(Roles([st.E EXCEPT ![e] = Absent], c.ts), c.au, o.tg)
  IN IF o.mb = o.tg \/ (o.tg = A /\ o.mb = 1) \/ ~DepthOK(o.tg) \/ <<c.id, k>> \in st.D
       THEN [a |-> -1, s |-> FALSE, on |-> o.tg]
     ELSE IF Lowers(nv, st.E[e], c.ts) /\ o.mb = c.au THEN [a |-> cls, s |-> TRUE, on |-> o.tg]
     ELSE IF Lowers(nv, st.E[e], c.ts) /\ o.mb \in Things /\ RoleOn(R, c.au, o.mb) = 3 /\ clsWithout < 2
       THEN [a |-> Class(R, c.au, o.mb), s |-> TRUE, on |-> o.mb]
     ELSE [a |-> IF cls >= 2 THEN cls ELSE -1, s |-> FALSE, on |-> o.tg]

RECURSIVE ApplyOps(_, _, _, _, _)
ApplyOps(st, c, js, k, t) ==
  IF k > Len(c.ops) THEN st
  ELSE IF js[k].a = -1 THEN ApplyOps(st, c, js, k + 1, t)
  ELSE LET o == c.ops[k]
           e == <<o.mb, o.tg>>
           nv == Norm([r |-> o.r, u |-> o.u], t)
           rec == [w |-> <<c.id, k>>, cid |-> c.id, au |-> c.au, tg |-> o.tg, attr |-> js[k].a, on |-> js[k].on,
                   key |-> c.key, gen |-> c.gen]
           st1 == [st EXCEPT !.app = @ \cup {rec}]
       IN ApplyOps(Change(st1, e, nv, t, c.key, c.au, js[k].a >= 2 /\ ~js[k].s, c.fr, c.id, c.gen),
                   c, js, k + 1, t)

Step(ev, st) ==
  LET t == ev.ts
      R == Roles(st.E, t)
  IN
  CASE ev.kind = "e" ->
         LET js == [k \in 1..Len(ev.ops) |-> Judge(st, R, ev, k)]
         IN UpdW(ApplyOps(st, ev, js, 1, t), ev.key, t)
    [] ev.kind = "c" ->
         LET ra == IF DepthOK(ev.tg) THEN RoleOn(R, ev.au, ev.tg) ELSE 0
         IN [st EXCEPT !.cinfo = @ \cup {[cid |-> ev.id, au |-> ev.au, tg |-> ev.tg, key |-> ev.key,
                gen |-> ev.gen, roleAt |-> ra, cls |-> Class(R, ev.au, ev.tg),
                ever |-> <<ev.au, ev.tg>> \in st.everW \/ ra >= 2]}]

\* One walk. stop: restart at the first write that adds to D (the spec);
\* else record each such write's additions in cands and go on.
RECURSIVE Pass(_, _, _, _)
Pass(evs, i, st, stop) ==
  IF i > Len(evs) THEN st
  ELSE LET s2 == Step(evs[i], st)
       IN IF s2.grow = {} THEN Pass(evs, i + 1, s2, stop)
          ELSE IF stop THEN s2
          ELSE Pass(evs, i + 1, [s2 EXCEPT !.cands = Append(@, s2.grow), !.grow = {}], stop)

\* §5.1 step 5: walk until a walk adds nothing to D. drecAll: every drop.
RECURSIVE WalkD(_, _, _)
WalkD(evs, D, acc) ==
  LET p == Pass(evs, 1, St0(D), TRUE)
  IN IF p.grow = {} THEN [p EXCEPT !.drec = acc \cup @]
     ELSE WalkD(evs, D \cup p.grow, acc \cup p.drec)

LTev(a, b) == Before(a.key, b.key)
Evs(h) == SortSeq(h, LTev)
W0 == WalkD(Evs(hist), {}, {})

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
(* Properties.                                                              *)
(***************************************************************************)
TypeOK == /\ Len(hist) <= MaxLen
          /\ \A c \in HSet : c.ts \in Nat

\* (1) Determinism: the verdicts do not depend on the order in which drops are
\* found (every write that adds to D may be taken first).
RECURSIVE WalkAll(_, _)
WalkAll(evs, D) ==
  LET p == Pass(evs, 1, St0(D), FALSE)
  IN IF p.cands = <<>> THEN {Verd(p)}
     ELSE UNION {WalkAll(evs, D \cup p.cands[j]) : j \in 1..Len(p.cands)}
DropOrderFree == Chaos => WalkAll(Evs(hist), {}) = {Verd(W0)}

\* (2) A holder whose class (or role) a valid explicit demotion R took away:
\* its edge writes generated after R and ordered before R are dropped; its
\* content generated after its newest demotion, with no regain, is invalid.
LateEdge == \A f \in W0.fall : \A a \in W0.app :
              (a.au = f.x /\ a.on = f.n /\ a.attr >= 2 /\ f.ca < a.attr /\ a.attr <= f.cb /\ a.gen > f.gen)
                => Before(f.key, a.key)
LateContent == \A c \in W0.cinfo :
  LET ds == {d \in W0.dem : d.x = c.au /\ d.n = c.tg}
  IN (ds # {} /\ c.gen > Newest(ds).gen /\ ~Before(Newest(ds).key, W0.lastW[<<c.au, c.tg>>])
      /\ RoleEnd(W0, c.au, c.tg) < 2) => ~CValid(W0, c)

\* (3) A demotion never drops its author's writes; a demoter that reached the
\* holder keeps its standing until the next explicit write on that edge,
\* which audits it.
NoSelfDrop == \A r \in W0.drec : r.au # r.byau
StandingAudited ==
  \A r1, r2 \in W0.ex :
    ( /\ r1.m = B /\ r2.m = B /\ r1.t = r2.t /\ Before(r1.key, r2.key) /\ r1.au # r2.au
      /\ r1.auReach /\ r1.was = 3 /\ r2.nv = Absent
      /\ r1.au \in r2.reachAdmin /\ r2.after[r1.au] < 2
      /\ ~\E r3 \in W0.ex : r3.m = B /\ r3.t = r1.t /\ Before(r1.key, r3.key) /\ Before(r3.key, r2.key) )
    => ~\E a \in W0.app : a.au = r1.au /\ a.on = r1.t /\ a.attr = 2 /\ Before(a.key, r1.key)
                           /\ a.cid \notin r2.fr

\* (4) Owner chain: chain authority confers write wherever the chain reaches
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
ProbeNoRestart == Cardinality(WalkAll(Evs(hist), {})) = 1 /\ Len(Pass(Evs(hist), 1, St0({}), FALSE).cands) <= 1

=============================================================================

-------------------------------- MODULE Tail --------------------------------
(* The pin (spec/crypto.md §4 Covers; notes/crypto.md The pin), checked over *)
(* every small history of one holder M's edge into an actor, read role.     *)
(* A world: M's start (its grant before any write, maybe timed) and N edge  *)
(* writes in key order, each a set (a value, maybe timed: past an `until`)  *)
(* or a finalize of the write whose entry it resets (`ends`, 0 the start:   *)
(* it applies only while that write is in force and timed, and is resolved  *)
(* only where that write is held, spec/permissions.md §2), voided wherever   *)
(* its invalidator is held (a demotion of its author ordered before it, or  *)
(* the audit dropping it), and, with Readers, maybe a reader's (a demotion  *)
(* to reader voids it, so it does not count). A view is the writes and      *)
(* invalidators (numbered above N) a node holds: any subset (commits arrive in any order).     *)
(* Rotator X names from its view (each applied write lowering M; each       *)
(* resolved write applying nothing that counts and gives a role, void) and  *)
(* its rotation commit may be one of the writes (its departs mark, m). Node *)
(* Z judges whether X's epoch covers M's departure (Rule "pin": the rule;   *)
(* "old": the per-event attribution it replaced). A node V meets the names  *)
(* (named writes held and resolved, void ones void there, the mark's commit *)
(* valid there) and boxes M into the epoch when M holds read at V.          *)
(* Safe: whenever Z takes X's epoch as covering, every V meeting its names  *)
(* (X included) holding M a reader does so on something Z has not          *)
(* received: M holds no read over V's view less what Z lacks. Own: X's own  *)
(* epoch covers what X knows (no livelock). Dup: an epoch whose rotation is *)
(* its own removal of M covers wherever more removals of M are held (one    *)
(* merge for concurrent removals). Controls: AnchorAny (a named write pins  *)
(* without taking M down: applying, or applying over the edge before it),  *)
(* NoVoid (void writes need no name),                                       *)
(* NoMark (the mark pins nothing), FromAnchor (the tail starts after the     *)
(* anchor, not after the newest write giving the role), MetHeld (a void name *)
(* is met by holding its write), MetBy "commit" (an applied name or the    *)
(* mark met by holding its commit however judged: with Inv2, an invalidator *)
(* voided where its own invalidator is held, a view lacking that judges a   *)
(* write Z applies void) and "takes" (met only where it takes: fails Live), *)
(* PinStands (a write standing at Z pins). Live: a view holding X's, it and *)
(* X judging no held write void by its author, meets X's names. Written from*)
(* spec/crypto.md §4.                                                       *)
EXTENDS Integers, FiniteSets

CONSTANTS N, Vals, Timed, Fins, Invs, Inv2, Readers, Starts0, Rule, AnchorAny, NoVoid, NoMark, FromAnchor, MetHeld, MetBy, PinStands

W == 1 .. N
R == 1                                   \* the role: read (values: 0 none, 1 read, 2 write)
Sets == {[k |-> "set", val |-> v, timed |-> t, ends |-> 0] : v \in Vals, t \in Timed}
FinSet == IF Fins THEN {[k |-> "fin", val |-> 0, timed |-> FALSE, ends |-> e] : e \in 0 .. N - 1} ELSE {}
WriteSet == {[k |-> x.k, val |-> x.val, timed |-> x.timed, ends |-> x.ends, inv |-> i, rd |-> d] :
               x \in Sets \cup FinSet, i \in {0} \cup Invs, d \in (IF Readers THEN BOOLEAN ELSE {FALSE})}

VARIABLES start, ws, meta, z
vars == <<start, ws, meta, z>>

Items == W \cup Invs \cup Inv2
Views == SUBSET Items

\* ---- the walk at a view V ------------------------------------------------
\* a finalize is resolved where the write it ends is held
Res(V, i) == ws[i].k # "fin" \/ ws[i].ends = 0 \/ ws[i].ends \in V
Held(V) == {i \in W \cap V : Res(V, i)}
\* an invalidator voided where its own invalidator (meta) is held: validity is not monotone
Valid(V, i) == ws[i].inv = 0 \/ ws[i].inv \notin V \/ meta[ws[i].inv] \in V
Applies(V, st, i) == i \in Held(V) /\ Valid(V, i)
                     /\ (ws[i].k = "fin" => st.src = ws[i].ends /\ st.timed /\ st.val > 0)
After(st, V, i) == IF Applies(V, st, i) THEN [val |-> ws[i].val, timed |-> ws[i].timed, src |-> i] ELSE st
RECURSIVE EdgeTo(_, _)
\* the edge just after write i (0: the start)
EdgeTo(V, i) == IF i = 0 THEN [val |-> start.val, timed |-> start.timed, src |-> 0] ELSE After(EdgeTo(V, i - 1), V, i)
Applied(V, i) == Applies(V, EdgeTo(V, i - 1), i)
Role(V) == EdgeTo(V, N).val
\* applying nothing, it counts unless a reader's demotion voided it there
Counts(V, i) == i \in Held(V) /\ ~Applied(V, i) /\ ~(ws[i].rd /\ ~Valid(V, i))
Departed(V) == Role(V) < R
\* the edge showed M a reader (its start, or a write that applies or counts)
Had(V) == start.val >= R \/ \E i \in Held(V) : ws[i].val >= R /\ (Applied(V, i) \/ Counts(V, i))

\* ---- names --------------------------------------------------------------
Newest(S) == IF S = {} THEN 0 ELSE CHOOSE i \in S : \A j \in S : j <= i
\* it takes M there: it applies, or would over the edge the newest applied write before it
\* giving more set (else the start)
Over(Zv, i) == LET ps == {j \in Held(Zv) : j < i /\ Applied(Zv, j) /\ ws[j].val > ws[i].val}
               IN IF ps = {} THEN EdgeTo(Zv, 0) ELSE EdgeTo(Zv, Newest(ps))
Takes(Zv, i) == Applied(Zv, i) \/ Applies(Zv, Over(Zv, i), i)
\* it stands there: it applies, or would over the start or the edge some applied write before it
\* set (only the edge it meets differs: a finalize of a grant renewed since, a second removal)
Stands(V, i) == Applied(V, i) \/ Applies(V, EdgeTo(V, 0), i)
                \/ \E j \in Held(V) : j < i /\ Applied(V, j) /\ Applies(V, EdgeTo(V, j), i)
\* how a named applied write (and the mark's) is met: "stands" (the rule), "takes", "commit"
\* (held, however judged)
MetOk(V, i) == CASE MetBy = "stands" -> Stands(V, i) [] MetBy = "takes" -> Takes(V, i) [] OTHER -> TRUE
Plain(X) == {i \in Held(X) : Applied(X, i) /\ ws[i].val < EdgeTo(X, i - 1).val}
\* a rotation commit cannot name itself
PlainOf(X, m) == Plain(X) \ {m}
Void(X) == {i \in Held(X) : Counts(X, i) /\ ws[i].val > 0}
\* the old rule's void names: raises only (above the edge just before)
OldVoid(X) == {i \in Void(X) : ws[i].val > EdgeTo(X, i - 1).val}
VoidOf(X) == IF Rule = "old" THEN OldVoid(X) ELSE Void(X)
\* the rotation commit's own write: X made it, so it applied at X, lowering M below the role
Marks(X) == {0} \cup {i \in Held(X) : Applied(X, i) /\ ws[i].val < R}
\* (the mark's commit is held: its rotation may stay valid where its edge write is void, its
\* author demoted to write)
\* each named write judged as X judged it: an applied one (and the mark's) standing at V, a void
\* one applying nothing there
Met(V, X, m) == /\ \A i \in PlainOf(X, m) : i \in Held(V) /\ MetOk(V, i)
                /\ \A i \in VoidOf(X) : i \in Held(V) /\ (MetHeld \/ ~Applied(V, i))
                /\ m # 0 => m \in Held(V) /\ MetOk(V, m)
MarkOk(Zv, m) == m # 0 /\ m \in Held(Zv)

\* ---- the pin -------------------------------------------------------------
\* the newest write applying at Z that gives the role or more (0: none)
G(Zv) == Newest({i \in Held(Zv) : Applied(Zv, i) /\ ws[i].val >= R})
Anchor(Zv, X, m, i) == ws[i].val < R /\ (AnchorAny \/ Takes(Zv, i) \/ (PinStands /\ Stands(Zv, i)))
                       /\ (i \in PlainOf(X, m) \/ (~NoMark /\ i = m /\ MarkOk(Zv, m)))
Pins(Zv, X, m) ==
  LET g == G(Zv)
      heldR == g > 0 \/ start.val >= R
      anchors == {i \in Held(Zv) : i > g /\ Anchor(Zv, X, m, i)}
      from == IF FromAnchor /\ anchors # {} THEN Newest(anchors) ELSE g
  IN /\ ~heldR \/ anchors # {}
     /\ NoVoid \/ \A i \in Held(Zv) : (i > from /\ ws[i].val >= R /\ Counts(Zv, i)) => i \in Void(X)

\* ---- the old rule: a departure attributed to its newest event -----------------
\* events: applied lowerings; raises applying nothing that count (spec before the pin)
RaiseEv(Zv) == OldVoid(Zv)
Events(Zv) == Plain(Zv) \cup RaiseEv(Zv)
OldNamed(Zv, X, m, i) == IF i \in RaiseEv(Zv) THEN i \in OldVoid(X)
                         ELSE i \in PlainOf(X, m) \/ (i = m /\ MarkOk(Zv, m))
OldCovers(Zv, X, m) ==
  LET at == Newest(Events(Zv))
      later == {i \in Held(Zv) : i > at /\ ws[i].val < R}
      since == {i \in RaiseEv(Zv) : i > Newest(Plain(Zv))}
  IN /\ at # 0
     /\ OldNamed(Zv, X, m, at) \/ \E i \in later : OldNamed(Zv, X, m, i)
     /\ \A i \in since : OldNamed(Zv, X, m, i)

Covers(Zv, X, m) == Departed(Zv) /\ Had(Zv) /\ Met(Zv, X, m)
                    /\ IF Rule = "old" THEN OldCovers(Zv, X, m) ELSE Pins(Zv, X, m)

\* ---- the search: every world and Z as an initial state; every X, mark and V in the invariants ----
Init == /\ start \in [val : Starts0, timed : Timed]
        /\ ws \in [W -> WriteSet]
        /\ meta \in [Invs -> {0} \cup Inv2]
        /\ \A i \in W : ws[i].ends < i
        /\ z \in Views
Next == UNCHANGED vars

Safe == \A X \in Views : \A m \in Marks(X) : Covers(z, X, m) =>
          \A V \in Views : (Met(V, X, m) /\ Role(V) >= R) => Role(V \cap z) < R
Own == (Departed(z) /\ Had(z)) => Covers(z, z, 0)
Removals == {i \in W : ws[i].val < R /\ ws[i].inv = 0}
Dup == \A X \in SUBSET z : \A m \in Marks(X) \ {0} :
         (z \ X \subseteq Removals /\ Departed(X) /\ Had(X)) => Covers(z, X, m)
\* a view holding X's where neither judges a held write void by its author meets its names (an
\* edge state X lacked, a renewal or another removal, does not hold the epoch back)
Live == \A X \in Views : \A m \in Marks(X) : \A V \in Views :
          (X \subseteq V /\ \A i \in Held(V) : Valid(V, i) /\ (i \in X => Valid(X, i))) => Met(V, X, m)
=============================================================================

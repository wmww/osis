------------------------------- MODULE Lockout --------------------------------
(* Rotating needs only the right to rotate (notes/crypto.md, Rotation needs  *)
(* no secret). One actor, one key role (read and write rotate together),     *)
(* nodes a (admin), h (honest writer), the rogue writers Rogues and j        *)
(* (granted by a's first removal). Each rogue rotates boxing itself and WBox *)
(* only, so that a and h hold no current secret; a removes each rogue once,  *)
(* in any order, with a full frontier (every rotation of it a received) and  *)
(* the rotation that removal requires: n above every current epoch, keyset   *)
(* listing every current epoch held or not, history box carrying the        *)
(* established secrets a holds. With Leave, a rogue may instead remove       *)
(* itself (no frontier, no rotation): its departure is uncovered and a's due *)
(* rotation recovers. Any holder of an earlier secret that no live history   *)
(* entry of a current epoch it holds lists adds one (HistAdd), unless that   *)
(* epoch misses a removal it knows (encrypting under a blocked epoch).       *)
(* Mode: "free" (the rule) or "none" (a locked a refuses, the negative       *)
(* control).                                                                 *)
(* HMissA: h's rotations leave a out (an honest epoch a lacks).              *)
(* Each honest node rotates up to MaxH times, plus up to MaxDue rotations a  *)
(* known uncovered removal (or a current epoch it cannot open) makes due.    *)
(* Commits arrive at each node in any order. Validity: a rogue's rotation is *)
(* valid at a node unless it holds that rogue's removal by a and the         *)
(* removal's frontier does not list it. Secrets: boxes, re-seals, then       *)
(* history entries of held commits at epochs held. An honest rotation names  *)
(* the removals its maker held, and is established where its secret is held *)
(* only with them held (names met).                                          *)
EXTENDS Naturals, FiniteSets

CONSTANTS Mode, Rogues, WBox, HMissA, Leave, MaxW, MaxH, MaxDue, Writes

Nodes == Rogues \cup {"a", "h", "j"}
Honest == {"a", "h"}
Readers == Honest \cup {"j"}

\* commit 0: epoch 0, everyone but j boxed, written by a
E0 == [ep |-> TRUE, n |-> 0, by |-> "a", listed |-> {}, hist |-> {}, boxed |-> Rogues \cup Honest,
       rm |-> "", self |-> FALSE, front |-> {}, names |-> {}, knows |-> {}, at |-> 0]

VARIABLES eps,     \* commit id (0..) -> commit: a rotation (ep), a removal (rm), both,
                   \* or a history add (at: the epoch its entry is at; a rotation's is itself)
          held,    \* node -> commits held
          content, \* honest content writes: [e, knows]
          nw,      \* rogue -> rotations it made
          nh,      \* honest node -> rotations it made
          rs       \* node -> epochs re-sealed to it (delivered with the box)

vars == <<eps, held, content, nw, nh, rs>>

Ids == DOMAIN eps
EIds == {e \in Ids : eps[e].ep}
IsAdd(c) == ~eps[c].ep /\ eps[c].rm = ""
\* the rogues whose removal (or leaving) v holds
RemOf(v) == {eps[r].rm : r \in {r2 \in held[v] : eps[r2].rm # ""}}

Valid(v, e) == eps[e].by \notin Rogues \/
               \A r \in held[v] : (eps[r].rm = eps[e].by /\ ~eps[r].self) => e \in eps[r].front

\* the history entries v holds at epochs in S open: what they carry
RECURSIVE Close(_, _, _)
Close(v, S, k) == IF k = 0 THEN S
                  ELSE Close(v, S \cup UNION {eps[c].hist : c \in {d \in held[v] : eps[d].at \in S}}, k - 1)
Secrets(v) == Close(v, {e \in held[v] \cap EIds : v \in eps[e].boxed} \cup rs[v], Cardinality(Ids))

\* established: held, valid, and, where v holds its secret, its names met (the removals its
\* maker held are held; spec/crypto.md §4, Established)
Est(v) == {e \in held[v] \cap EIds : Valid(v, e) /\ (e \in Secrets(v) => eps[e].names \subseteq held[v])}
Cur(S) == {e \in S : ~\E f \in S : e \in eps[f].listed}
Current(v) == Cur(Est(v))
\* the removal commits v holds
RCs(v) == {r \in held[v] : eps[r].rm # ""}

MaxN(S) == CHOOSE m \in {eps[e].n : e \in S} : \A e \in S : eps[e].n <= m
\* the holders v boxes: the rogues it has not removed, j once any removal is known
Holders(v) == Honest \cup (Rogues \ RemOf(v)) \cup (IF RemOf(v) # {} THEN {"j"} ELSE {})

\* names: the removal commits the maker holds; knows: the removals it covers (a removal's
\* own rotation covers that removal too)
New(by, S, hist, boxed, rm, front, names, knows) ==
  [ep |-> TRUE, n |-> MaxN(S) + 1, by |-> by, listed |-> S, hist |-> hist, boxed |-> boxed,
   rm |-> rm, self |-> FALSE, front |-> front, names |-> names, knows |-> knows, at |-> 0]
Alone(by, rm, front, self) ==
  [ep |-> FALSE, n |-> 0, by |-> by, listed |-> {}, hist |-> {}, boxed |-> {},
   rm |-> rm, self |-> self, front |-> front, names |-> {}, knows |-> {}, at |-> 0]
HAdd(by, e, hist) ==
  [ep |-> FALSE, n |-> 0, by |-> by, listed |-> {}, hist |-> hist, boxed |-> {},
   rm |-> "", self |-> FALSE, front |-> {}, names |-> {}, knows |-> {}, at |-> e]

Add(r, v) ==
  LET id == Cardinality(Ids)
      c == IF r.ep THEN [r EXCEPT !.at = id] ELSE r
  IN /\ eps' = [i \in Ids \cup {id} |-> IF i = id THEN c ELSE eps[i]]
     /\ held' = [held EXCEPT ![v] = @ \cup {id}]

\* rogue x rotates from its own current epochs (validity ignored), boxing itself and WBox
RogueRotate(x) ==
  /\ nw[x] < MaxW
  /\ LET c == Cur(held[x] \cap EIds) IN
       Add(New(x, c, Secrets(x) \cap held[x], {x} \cup WBox, "", {}, {}, {}), x)
  /\ nw' = [nw EXCEPT ![x] = @ + 1]
  /\ UNCHANGED <<content, nh, rs>>

\* rogue x removes itself: no frontier, no rotation (Leave)
RogueLeave(x) ==
  /\ Leave /\ x \notin RemOf(x)
  /\ Add(Alone(x, x, {}, TRUE), x)
  /\ UNCHANGED <<content, nw, nh, rs>>

\* a current epoch of v does not cover a removal v knows of (one whose secret v lacks covers
\* nothing: its history box is closed): a rotation is due
Due(v) == RemOf(v) # {} /\ \E e \in Current(v) : e \notin Secrets(v) \/ ~(RemOf(v) \subseteq eps[e].knows)

\* an honest node rotates holding any secret to wrap under, no current one needed
HonestRotate(v) ==
  /\ nh[v] < MaxH \/ (Due(v) /\ nh[v] < MaxH + MaxDue)
  /\ Secrets(v) # {}
  /\ LET c == Current(v) IN
       Add(New(v, c, Secrets(v) \cap Est(v),
               IF HMissA /\ v = "h" THEN Holders(v) \ {"a"} ELSE Holders(v), "", {}, RCs(v), RemOf(v)), v)
  /\ nh' = [nh EXCEPT ![v] = @ + 1]
  /\ UNCHANGED <<content, nw, rs>>

Locked == Current("a") \cap Secrets("a") = {}
Rotates == ~Locked \/ Mode = "free"
CanRemove(x) == x \notin RemOf("a") /\ Rotates

\* a removes rogue x: the rotation it requires goes in the same commit
Remove(x) ==
  /\ CanRemove(x)
  /\ LET c == Current("a")
         mine == Secrets("a") \cap Est("a")
         front == {e \in held["a"] \cap EIds : eps[e].by = x}
         rm == RemOf("a") \cup {x}
     IN Add(New("a", c, mine, Honest \cup {"j"} \cup (Rogues \ rm), x, front, RCs("a"), rm), "a")
  /\ UNCHANGED <<content, nw, nh, rs>>

\* what the live history entries v holds at e list
ListedAt(v, e) == UNION {eps[c].hist : c \in {d \in held[v] : eps[d].at = e}}
\* v may add at e: a current epoch it holds established that covers every removal it knows
AddAt(v, e) == e \in Current(v) \cap Secrets(v) /\ RemOf(v) \subseteq eps[e].knows
Carry(v, e) == {f \in (Secrets(v) \cap Est(v)) \ Current(v) : eps[f].n < eps[e].n}
AddDue(v, e) == AddAt(v, e) /\ ~(Carry(v, e) \subseteq ListedAt(v, e))

\* a holder adds the earlier established secrets it holds that no entry at e lists
HistAdd(v, e) ==
  /\ AddDue(v, e)
  /\ Add(HAdd(v, e, Carry(v, e)), v)
  /\ UNCHANGED <<content, nw, nh, rs>>

\* an honest write under a current epoch it holds that covers every removal it knows of
Write(v) ==
  /\ Cardinality(content) < Writes
  /\ \E e \in Current(v) \cap Secrets(v) :
       /\ RemOf(v) \subseteq eps[e].knows
       /\ content' = content \cup {[e |-> e, knows |-> RemOf(v)]}
  /\ UNCHANGED <<eps, held, nw, nh, rs>>

\* honest v re-seals a current honest holder u lacking a current epoch v holds
\* (spec/permissions.md §3 Re-seal); the box arrives with the epoch's commit.
\* Only under HMissA (elsewhere every honest rotation boxes every honest holder)
Reseal(v, u) ==
  /\ HMissA
  /\ u \in Holders(v) \ ({v} \cup Rogues)
  /\ \E e \in Current(v) \cap Secrets(v) :
       /\ e \notin Secrets(u)
       /\ rs' = [rs EXCEPT ![u] = @ \cup {e}]
       /\ held' = [held EXCEPT ![u] = @ \cup {e}]
  /\ UNCHANGED <<eps, content, nw, nh>>

Deliver(v) == \E e \in Ids \ held[v] :
  /\ held' = [held EXCEPT ![v] = @ \cup {e}]
  /\ UNCHANGED <<eps, content, nw, nh, rs>>

Init == /\ eps = [i \in {0} |-> E0]
        /\ held = [v \in Nodes |-> IF v = "j" THEN {} ELSE {0}]
        /\ content = {}
        /\ nw = [x \in Rogues |-> 0] /\ nh = [v \in Honest |-> 0]
        /\ rs = [v \in Nodes |-> {}]

Next == (\E x \in Rogues : RogueRotate(x) \/ RogueLeave(x) \/ Remove(x))
        \/ (\E v \in Honest : HonestRotate(v) \/ Write(v))
        \/ (\E v \in Readers, e \in EIds : HistAdd(v, e))
        \/ (\E v \in Honest, u \in Nodes : Reseal(v, u))
        \/ (\E u \in Nodes : Deliver(u))

Spec == Init /\ [][Next]_vars

\* ---- properties ----
\* every rogue removed, every honest node, j included, holds every commit made, no history add
\* is due, and (with MaxDue) no honest node owes a rotation: a state where one does but has
\* spent MaxDue is cut short, not settled
Settled == /\ RemOf("a") = Rogues /\ \A v \in Readers : held[v] = Ids
           /\ ~\E v \in Readers, e \in EIds : AddDue(v, e)
           /\ ~(MaxDue > 0 /\ \E v \in Honest : Due(v))

\* no rogue holds a secret an honest node wrote under once it knew of that rogue's removal
NoLeak == \A c \in content : \A x \in c.knows : c.e \notin Secrets(x)

\* settled: nobody is locked out: every honest node and j holds every current epoch
Unlocked == Settled => \A v \in Readers : Current(v) # {} /\ Current(v) \subseteq Secrets(v)
Alike == Settled => Current("a") = Current("h") /\ Current("h") = Current("j")

\* settled: every honest node and j reads every honest write (older epochs by history)
ReadsAll == Settled => \A c \in content : \A v \in Readers : c.e \in Secrets(v)

\* a rogue a has yet to remove can be removed (fails under "none")
RemoveOK == \A x \in Rogues \ RemOf("a") : CanRemove(x)

\* probe (expected to fail): a recovery superseding a rogue epoch a never held is reached
\* and settles
ProbeRecovered == ~(Settled /\ \E r \in Ids, e \in Ids :
                      eps[r].rm # "" /\ e \in eps[r].listed /\ eps[e].by \in Rogues /\ e \notin Secrets("a"))
\* probe (expected to fail): a history add is reached
ProbeAdded == ~\E c \in Ids : IsAdd(c)
===============================================================================

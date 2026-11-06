------------------------------- MODULE Lockout --------------------------------
(* Lockout recovery without frontier omission (notes/lockout-recovery.md).   *)
(* One actor, one key role (read and write rotate together), nodes a (admin), *)
(* h (honest writer), the rogue writers Rogues and j (granted by a's first    *)
(* removal). Each rogue rotates boxing itself and WBox only; a removes each   *)
(* rogue once, in any order, with a full frontier (every rotation of it a     *)
(* received) and, where it can, the rotation that removal requires.           *)
(* Mode decides that rotation when a holds no current secret:                 *)
(*   "list": the built rule: an ordinary rotation (n above every current      *)
(*           epoch, keyset listing every current epoch, held or not), made   *)
(*           when every current epoch a lacks was made by a node holding no  *)
(*           write once this removal applies; else the removal goes alone    *)
(*           (its departure uncovered: no node knowing it writes until one   *)
(*           that may rotates);                                              *)
(*   "own":  the removed rogue alone made every lacked epoch; else refused   *)
(*           (two rogues lock it for good: negative control);                *)
(*   "fork": from the epochs a holds only (a fork beside the rogues');       *)
(*   "none": refused (no recovery).                                          *)
(* HMissA: h's rotations leave a out (an honest epoch a lacks).              *)
(* h rotates up to MaxH times, plus up to MaxDue rotations a known uncovered *)
(* removal makes due. Commits arrive at each node in any order. Validity: a  *)
(* rogue's rotation is valid at a node unless it holds that rogue's removal  *)
(* and the removal's frontier does not list it. Secrets: boxes, re-seals,    *)
(* then history boxes of held commits. An honest rotation names the removals *)
(* its maker held; a node holding its secret establishes it once it holds    *)
(* them (names met).                                                         *)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Mode, Rogues, WBox, HMissA, MaxW, MaxH, MaxDue, Writes

Nodes == Rogues \cup {"a", "h", "j"}
Honest == {"a", "h"}

\* commit 0: epoch 0, everyone but j boxed, written by a
E0 == [ep |-> TRUE, n |-> 0, by |-> "a", listed |-> {}, hist |-> {}, boxed |-> Rogues \cup Honest,
       rm |-> "", front |-> {}, names |-> {}, knows |-> {}]

VARIABLES eps,     \* commit id (0..) -> commit: a rotation (ep), a removal (rm), or both
          held,    \* node -> commits held
          content, \* honest content writes: [e, knows]
          nw,      \* rogue -> rotations it made
          nh,      \* rotations made by h
          rs       \* node -> epochs re-sealed to it (delivered with the box)

vars == <<eps, held, content, nw, nh, rs>>

Ids == DOMAIN eps
EIds == {e \in Ids : eps[e].ep}
\* the rogues whose removal v holds
RemOf(v) == {eps[r].rm : r \in {r2 \in held[v] : eps[r2].rm # ""}}

Valid(v, e) == eps[e].by \notin Rogues \/
               \A r \in held[v] : eps[r].rm = eps[e].by => e \in eps[r].front

RECURSIVE Close(_, _, _)
Close(v, S, k) == IF k = 0 THEN S
                  ELSE Close(v, S \cup UNION {eps[e].hist : e \in held[v] \cap S}, k - 1)
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
   rm |-> rm, front |-> front, names |-> names, knows |-> knows]
Alone(rm, front) ==
  [ep |-> FALSE, n |-> 0, by |-> "a", listed |-> {}, hist |-> {}, boxed |-> {},
   rm |-> rm, front |-> front, names |-> {}, knows |-> {}]

Add(r, v) ==
  /\ eps' = [i \in Ids \cup {Cardinality(Ids)} |-> IF i = Cardinality(Ids) THEN r ELSE eps[i]]
  /\ held' = [held EXCEPT ![v] = @ \cup {Cardinality(Ids)}]

\* rogue x rotates from its own current epochs (validity ignored), boxing itself and WBox
RogueRotate(x) ==
  /\ nw[x] < MaxW
  /\ LET c == Cur(held[x] \cap EIds) IN
       Add(New(x, c, Secrets(x) \cap held[x], {x} \cup WBox, "", {}, {}, {}), x)
  /\ nw' = [nw EXCEPT ![x] = @ + 1]
  /\ UNCHANGED <<content, nh, rs>>

\* a current epoch of v does not cover a removal v knows of: a rotation is due
Due(v) == \E e \in Current(v) : ~(RemOf(v) \subseteq eps[e].knows)

\* h rotates as today: only while holding a current secret
HonestRotate ==
  /\ nh < MaxH \/ (Due("h") /\ nh < MaxH + MaxDue)
  /\ Current("h") \cap Secrets("h") # {}
  /\ LET c == Current("h") IN
       Add(New("h", c, Secrets("h") \cap Est("h"),
               IF HMissA THEN Holders("h") \ {"a"} ELSE Holders("h"), "", {}, RCs("h"), RemOf("h")), "h")
  /\ nh' = nh + 1
  /\ UNCHANGED <<content, nw, rs>>

Locked == Current("a") \cap Secrets("a") = {}
Lacked == Current("a") \ Secrets("a")
\* the writers once a's removal of x applies
WritersAfter(x) == {"h"} \cup (Rogues \ (RemOf("a") \cup {x}))
\* the lacked current epochs that block the removal's rotation
Blocking(x) == CASE Mode = "list" -> {e \in Lacked : eps[e].by \in WritersAfter(x)}
                 [] Mode = "own"  -> {e \in Lacked : eps[e].by # x}
                 [] OTHER -> Lacked
Rotates(x) == ~Locked \/ Mode = "fork" \/ Blocking(x) = {}
CanRemove(x) == x \notin RemOf("a") /\ (Rotates(x) \/ Mode = "list")

\* a removes rogue x: the rotation it requires goes in the same commit, or (Mode "list",
\* when it cannot be made) the removal goes alone
Remove(x) ==
  /\ CanRemove(x)
  /\ LET c == Current("a")
         mine == Secrets("a") \cap Est("a")
         base == IF Mode = "fork" /\ Locked THEN Cur(mine) ELSE c
         front == {e \in held["a"] \cap EIds : eps[e].by = x}
         rm == RemOf("a") \cup {x}
     IN Add(IF Rotates(x)
            THEN New("a", base, mine, Honest \cup {"j"} \cup (Rogues \ rm), x, front, RCs("a"), rm)
            ELSE Alone(x, front), "a")
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
\* Only under HMissA (elsewhere no honest holder needs one before settling).
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
        /\ nw = [x \in Rogues |-> 0] /\ nh = 0
        /\ rs = [v \in Nodes |-> {}]

Next == (\E x \in Rogues : RogueRotate(x) \/ Remove(x)) \/ HonestRotate
        \/ (\E v \in Honest : Write(v))
        \/ (\E v \in Honest, u \in Nodes : Reseal(v, u))
        \/ (\E u \in Nodes : Deliver(u))

Spec == Init /\ [][Next]_vars
\* the rogues are interchangeable (model values in the two-rogue instances)
RogueSym == Permutations(Rogues)

\* ---- properties ----
\* every rogue removed, every honest node, j included, holds every commit made, and (with
\* MaxDue) h owes no rotation (a current epoch not covering a removal it knows of): a state
\* where it does but has spent MaxDue is cut short, not settled
Settled == /\ RemOf("a") = Rogues /\ \A v \in {"a", "h", "j"} : held[v] = Ids
           /\ ~(MaxDue > 0 /\ Due("h") /\ Current("h") \cap Secrets("h") # {})

\* no rogue holds a secret an honest node wrote under once it knew of that rogue's removal
NoLeak == \A c \in content : \A x \in c.knows : c.e \notin Secrets(x)

\* no rogue holds the secret of an honest epoch whose maker knew of its removal (stronger
\* than NoLeak, for instances with no writes; WBox must not box another rogue, since a kept
\* rogue may hand on what it holds)
NoKeyLeak == \A e \in EIds : eps[e].by \in Honest => \A x \in eps[e].knows : e \notin Secrets(x)

\* settled: a and h are not locked out (unless h left a out); a current epoch an
\* honest node or j lacks (a rotation by h made before it held a removal, or
\* leaving a out) is held by an honest node that may re-seal it
Unlocked == Settled =>
              /\ \A v \in Honest : Current(v) # {}
              /\ ~HMissA => \A v \in Honest : Current(v) \subseteq Secrets(v)
              /\ \A v \in {"a", "h", "j"} : \A e \in Current(v) \ Secrets(v) :
                   \E u \in Honest : e \in Secrets(u)
Alike == Settled => Current("a") = Current("h") /\ Current("h") = Current("j")

\* settled: content under an epoch j lacks is held by an honest node that may
\* still rotate (its next rotation's history box carries it to j)
Repairable == Settled => \A c \in content :
                c.e \in Est("j") /\ c.e \notin Secrets("j") =>
                  \E v \in Honest : c.e \in Secrets(v) /\ Current(v) \cap Secrets(v) # {}

\* a rogue a has yet to remove can be removed, or what blocks it is held by an
\* honest node, which re-seals a or holds a newer rotation a has yet to receive
\* (fails under "none", and under "own" with two rogues)
RemoveOK == \A x \in Rogues \ RemOf("a") :
              CanRemove(x) \/ \A e \in Blocking(x) : \E v \in Honest : e \in Secrets(v)

\* probe (expected to fail): a recovery superseding a rogue's epoch that a never held
\* is reached and settles
ProbeRecovered == ~(Settled /\ \E r \in Ids, e \in Ids :
                      eps[r].rm # "" /\ e \in eps[r].listed /\ eps[e].by \in Rogues /\ e \notin Secrets("a"))

\* probe (expected to fail under HMissA): the rule's refusal is reached, a removal
\* that cannot rotate (it goes alone under "list")
ProbeRefused == ~\E x \in Rogues \ RemOf("a") : ~Rotates(x)
===============================================================================

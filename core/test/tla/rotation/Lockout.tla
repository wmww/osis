------------------------------- MODULE Lockout --------------------------------
(* Lockout recovery without frontier omission (notes/lockout-recovery.md).   *)
(* One actor, one key role (read and write rotate together), nodes a (admin), *)
(* h (honest writer), w (the rotating writer) and j (granted by a's removal   *)
(* of w). w rotates boxing WBox only; a removes w once, with a full frontier  *)
(* (every rotation of w it received) and the rotation that removal requires. *)
(* Mode decides that rotation when a holds no current secret:                 *)
(*   "list": the built rule: an ordinary rotation (n above every current      *)
(*           epoch, keyset listing every current epoch, held or not), made   *)
(*           only when every current epoch a lacks was made by w; else a     *)
(*           waits for a re-seal by an honest holder;                        *)
(*   "fork": from the epochs a holds only (a fork beside w's epoch);         *)
(*   "none": refused (no recovery).                                          *)
(* HMissA: h's rotations leave a out (an honest epoch a lacks, not w's).      *)
(* Commits arrive at each node in any order. Validity: w's rotation is valid  *)
(* at a node unless it holds the removal and the removal's frontier does not *)
(* list it. Secrets: boxes, then history boxes of held commits.              *)
EXTENDS Naturals, FiniteSets

CONSTANTS Mode, WBox, HMissA, MaxW, MaxH, Writes

Nodes == {"a", "h", "w", "j"}
Honest == {"a", "h"}

\* epoch 0: everyone but j boxed, written by a
E0 == [n |-> 0, by |-> "a", listed |-> {}, hist |-> {}, boxed |-> {"a", "h", "w"},
       rem |-> FALSE, front |-> {}, knowsR |-> FALSE]

VARIABLES eps,     \* epoch id (0..) -> its rotation commit
          held,    \* node -> rotation commits held
          content, \* honest content writes: [e, knowsR]
          nw, nh,  \* rotations made by w, by h
          rs       \* node -> epochs re-sealed to it (delivered with the box)

vars == <<eps, held, content, nw, nh, rs>>

Ids == DOMAIN eps
RIds == {e \in Ids : eps[e].rem}
RHeld(v) == RIds \cap held[v] # {}
RMade == RIds # {}
Front == UNION {eps[e].front : e \in RIds}

Valid(v, e) == eps[e].by # "w" \/ ~RHeld(v) \/ e \in Front
Est(v) == {e \in held[v] : Valid(v, e)}
Cur(S) == {e \in S : ~\E f \in S : e \in eps[f].listed}
Current(v) == Cur(Est(v))

RECURSIVE Close(_, _, _)
Close(v, S, k) == IF k = 0 THEN S
                  ELSE Close(v, S \cup UNION {eps[e].hist : e \in held[v] \cap S}, k - 1)
Secrets(v) == Close(v, {e \in held[v] : v \in eps[e].boxed} \cup rs[v], Cardinality(Ids))

MaxN(S) == CHOOSE m \in {eps[e].n : e \in S} : \A e \in S : eps[e].n <= m
Holders(v) == IF RHeld(v) THEN {"a", "h", "j"} ELSE {"a", "h", "w"}

New(by, S, listed, hist, boxed, rem, front, kr) ==
  [n |-> IF S = {} THEN 1 ELSE MaxN(S) + 1, by |-> by, listed |-> listed,
   hist |-> hist, boxed |-> boxed, rem |-> rem, front |-> front, knowsR |-> kr]

Add(r, v) ==
  /\ eps' = [i \in Ids \cup {Cardinality(Ids)} |-> IF i = Cardinality(Ids) THEN r ELSE eps[i]]
  /\ held' = [held EXCEPT ![v] = @ \cup {Cardinality(Ids)}]

\* w rotates from its own current epochs (validity ignored), boxing WBox only
RogueRotate ==
  /\ nw < MaxW
  /\ LET c == Cur(held["w"]) IN
       Add(New("w", c, c, Secrets("w") \cap held["w"], WBox, FALSE, {}, FALSE), "w")
  /\ nw' = nw + 1
  /\ UNCHANGED <<content, nh, rs>>

\* h rotates as today: only while holding a current secret
HonestRotate ==
  /\ nh < MaxH
  /\ Current("h") \cap Secrets("h") # {}
  /\ LET c == Current("h") IN
       Add(New("h", c, c, Secrets("h") \cap Est("h"),
               IF HMissA THEN Holders("h") \ {"a"} ELSE Holders("h"), FALSE, {}, RHeld("h")), "h")
  /\ nh' = nh + 1
  /\ UNCHANGED <<content, nw, rs>>

Locked == Current("a") \cap Secrets("a") = {}
\* current epochs a lacks that w did not make
Foreign == {e \in Current("a") \ Secrets("a") : eps[e].by # "w"}
CanRemove == ~RMade /\ CASE Mode = "none" -> ~Locked
                         [] Mode = "list" -> Foreign = {}
                         [] Mode = "fork" -> TRUE

\* a removes w; the rotation it requires goes in the same commit
Remove ==
  /\ CanRemove
  /\ LET c == Current("a")
         mine == Secrets("a") \cap Est("a")
         base == IF Mode = "fork" /\ Locked THEN Cur(mine) ELSE c
     IN Add(New("a", base, base, mine, {"a", "h", "j"}, TRUE,
                {e \in held["a"] : eps[e].by = "w"}, TRUE), "a")
  /\ UNCHANGED <<content, nw, nh, rs>>

\* an honest write under a current epoch it holds that covers the removal it knows of
Write(v) ==
  /\ Cardinality(content) < Writes
  /\ \E e \in Current(v) \cap Secrets(v) :
       /\ RHeld(v) => eps[e].knowsR
       /\ content' = content \cup {[e |-> e, knowsR |-> RHeld(v)]}
  /\ UNCHANGED <<eps, held, nw, nh, rs>>

\* honest v re-seals a current holder u lacking a current epoch v holds
\* (spec/permissions.md §3 Re-seal); the box arrives with the epoch's commit.
\* Only under HMissA (elsewhere no honest holder needs one before settling).
Reseal(v, u) ==
  /\ HMissA
  /\ u \in Holders(v) \ {v, "w"}
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
        /\ nw = 0 /\ nh = 0
        /\ rs = [v \in Nodes |-> {}]

Next == RogueRotate \/ HonestRotate \/ Remove
        \/ (\E v \in Honest : Write(v))
        \/ (\E v \in Honest, u \in Nodes : Reseal(v, u))
        \/ (\E u \in Nodes : Deliver(u))

Spec == Init /\ [][Next]_vars

\* ---- properties ----
\* every honest node, j included, holds every commit made, after the removal
Settled == RMade /\ \A v \in {"a", "h", "j"} : held[v] = Ids

\* the removed writer never holds a secret an honest node wrote under once it knew
NoLeak == \A c \in content : c.knowsR => c.e \notin Secrets("w")

\* settled: a and h are not locked out (unless h left a out); a current epoch an
\* honest node or j lacks (a rotation by h made before it held the removal, or
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

\* probe (expected to fail): a recovery superseding an epoch of w that a never held
\* is reached and settles
ProbeRecovered == ~(Settled /\ \E e \in Front : e \notin Secrets("a") /\ e \in Cur(Ids \ RIds))

\* the removal can be made, or what blocks it (an epoch a lacks that w did not
\* make) is held by an honest node, which re-seals a or holds a newer rotation a
\* has yet to receive (fails under "none")
Blocking == IF Mode = "list" THEN Foreign ELSE Current("a") \ Secrets("a")
RemoveOK == ~RMade => CanRemove \/ (Blocking # {} /\ \A e \in Blocking : \E v \in Honest : e \in Secrets(v))

\* probe (expected to fail under HMissA): the rule's refusal is reached
ProbeRefused == ~(~RMade /\ ~CanRemove)
===============================================================================

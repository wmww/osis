------------------------------- MODULE FireKey --------------------------------
(* What an outsider seals a fire to (spec/crypto.md §3 Read key in force,    *)
(* spec/sync-inbox.md §2). One thing T, read role only (an honest rotation   *)
(* also rotates sync: spec/permissions.md §3 step triggers). Actors: admin A *)
(* (honest, the only stepper), honest writer W1, malicious writer W2, reader *)
(* R (removed at most once, by A or W1, with the rotation the removal        *)
(* carries), outsider O holding only `keys.0`. Crypto as access: an epoch's  *)
(* secret is held by those its rotation boxes; its keyset's KEM key is       *)
(* genuine or junk (W2 only).                                                *)
(* `keys.0` is the LWW merge of the commits a node holds: the `read` field   *)
(* (every rotation writes it; one keyset value) and the step keys (A's steps;*)
(* the read key: the registered epoch, the genuine key A derives, and `seen`,*)
(* the keyset the `read` field held at A when it stepped). Stamps order LWW  *)
(* fields only:                                                              *)
(* (ts, actor); an honest commit stamps above every stamp it holds; W2 picks *)
(* any ts in 1..MaxTs (a malicious clock). Commits reach A and O in any      *)
(* order; W2 holds every commit; W1 rotates holding any set of commits that  *)
(* includes its own (its view is not kept as state: a smaller space, and     *)
(* every order of receipt).                                                  *)
(* Rule: "digest" the spec (seal to the step's read key while the `read`     *)
(* field holds the keyset its `seen` names; none in force: pending);         *)
(* "stamps" the step's read key while the `read` field's stamp is no later   *)
(* than the step's (negative control, finding F1); "newest" seal to the      *)
(* `read` field's keyset (negative control); "nopend" seal to the step's     *)
(* read key whatever the `read` field holds (negative control).              *)
(* Fires: the sender reseals to the key in force whenever it changes before  *)
(* a peer takes it, and a peer may take it in any state, so a fire is not    *)
(* state: the invariants judge the key O would seal to in every state, the   *)
(* liveness property that O comes to hold one for good.                      *)
(* A steps when due (no read key in force; or it holds a read epoch newer    *)
(* than its head registers), never while read is blocked at it (it knows R's *)
(* removal and a current epoch does not cover it: it rotates first, ARotDue),*)
(* and up to OptSteps times unprompted (MAY, spec/sync-ids.md §6 Steps).     *)
(* W2 never boxes R: a writer handing R a secret is a leak by hand, outside  *)
(* any key rule (threat model: writers bounded, not prevented).              *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Rule,     \* "digest" | "stamps" | "newest" | "nopend"
          HMax,     \* unprompted honest rotations (the removal included)
          W2Max,    \* W2's rotations
          MaxTs,    \* W2's stamps: ts in 1..MaxTs
          OptSteps  \* unprompted steps by A

Honest == {"A", "W1"}
Rank == [A |-> 1, W1 |-> 2, W2 |-> 3]
Viewers == {"A", "O"}
\* W2's keysets: genuine boxing nobody, itself only (the lockout), A beside it or
\* every writer; or junk (no box opens it)
W2Keys == {<<TRUE, b>> : b \in {{}, {"W2"}, {"A", "W2"}, {"A", "W1", "W2"}}} \cup {<<FALSE, {"W2"}>>}

\* reg, ks: a step's registered epoch and `seen` keyset (a rotation commit id)
Rec(k, by, n, gen, ts, boxed, sup, rm, knows, saw, reg, ks) ==
  [k |-> k, by |-> by, n |-> n, gen |-> gen, ts |-> ts, boxed |-> boxed,
   sup |-> sup, rm |-> rm, knows |-> knows, saw |-> saw, reg |-> reg, ks |-> ks]

\* the minting commit: epoch 1 boxed to everyone, and its step keys (one stamp)
Init0 == << Rec("rot", "A", 0, TRUE, 0, {"A", "W1", "W2", "R"}, {}, FALSE, FALSE, {}, 0, 0),
            Rec("step", "A", 0, TRUE, 0, {}, {}, FALSE, FALSE, {1}, 1, 1) >>

VARIABLES cm,     \* commit id -> commit
          seen,   \* viewer -> ids it holds
          hrot, w2n, opt

vars == <<cm, seen, hrot, w2n, opt>>

Ids == 1..Len(cm)
Less(i, j) == cm[i].ts < cm[j].ts \/ (cm[i].ts = cm[j].ts /\ Rank[cm[i].by] < Rank[cm[j].by])
Last(S) == CHOOSE i \in S : \A j \in S : ~Less(i, j)
Rots(S) == {i \in S : cm[i].k = "rot"}
StepsIn(S) == {i \in S : cm[i].k = "step"}
ReadF(S) == Last(Rots(S))
StepF(S) == Last(StepsIn(S))
MaxTsIn(S) == LET m == CHOOSE i \in S : \A j \in S : cm[j].ts <= cm[i].ts IN cm[m].ts
MaxN(S) == LET m == CHOOSE i \in Rots(S) : \A j \in Rots(S) : cm[j].n <= cm[i].n IN cm[m].n
Current(S) == Rots(S) \ UNION {cm[i].sup : i \in Rots(S)}
Removed == \E i \in Ids : cm[i].rm
Knows(S) == \E i \in S : cm[i].rm

None == [ep |-> 0, gen |-> FALSE, src |-> 0]
StepKey(s) == [ep |-> cm[s].reg, gen |-> TRUE, src |-> s]
FieldKey(r) == [ep |-> r, gen |-> cm[r].gen, src |-> r]
\* the read key in force at a node holding S (spec/crypto.md §3)
InForce(S) ==
  IF Rule = "stamps" THEN IF ~Less(StepF(S), ReadF(S)) THEN StepKey(StepF(S)) ELSE None
  ELSE IF cm[StepF(S)].ks = ReadF(S) THEN StepKey(StepF(S)) ELSE None
SealKey(S) ==
  CASE Rule \in {"digest", "stamps"} -> InForce(S)
    [] Rule = "newest" -> FieldKey(ReadF(S))
    [] Rule = "nopend" -> StepKey(StepF(S))

\* A's newest read epoch it holds: greatest n, ties by lowest id
AHeld == {i \in Rots(seen["A"]) : "A" \in cm[i].boxed}
ANewest == CHOOSE i \in AHeld : \A j \in AHeld : cm[j].n < cm[i].n \/ (cm[j].n = cm[i].n /\ i <= j)
\* covering R's departure: its rotator knew of it (an epoch A lacks, by order: the same here)
ABlocked == Knows(seen["A"]) /\ \E e \in Current(seen["A"]) : ~cm[e].knows
ADue == InForce(seen["A"]) = None \/ ANewest # cm[StepF(seen["A"])].reg

Init ==
  /\ cm = Init0
  /\ seen = [v \in Viewers |-> {1, 2}]
  /\ hrot = 0 /\ w2n = 0 /\ opt = 0

NewCommit(c, v) ==
  /\ cm' = Append(cm, c)
  /\ seen' = IF v = "" THEN seen ELSE [seen EXCEPT ![v] = @ \cup {Len(cm) + 1}]

\* an honest rotation of read (and sync): boxes every current holder it knows of
HRot(a, S, rm) ==
  LET kn == Knows(S) \/ rm
  IN NewCommit(Rec("rot", a, MaxN(S) + 1, TRUE, MaxTsIn(S) + 1,
                   {"A", "W1", "W2"} \cup (IF kn THEN {} ELSE {"R"}),
                   Current(S), rm, kn, S, 0, 0), IF a = "A" THEN "A" ELSE "")
\* what W1 may hold when it rotates: the minting commit, its own, any others
W1Views == {{1, 2} \cup {i \in Ids : cm[i].by = "W1"} \cup X : X \in SUBSET (Ids \ {1, 2})}

HonestRot(a) ==
  /\ hrot < HMax
  /\ \E rm \in (IF Removed THEN {FALSE} ELSE BOOLEAN),
       S \in (IF a = "A" THEN {seen["A"]} ELSE W1Views) : HRot(a, S, rm)
  /\ hrot' = hrot + 1
  /\ UNCHANGED <<w2n, opt>>

\* spec/crypto.md §4 Encrypting under: A rotates before it steps under a blocked epoch
ARotDue ==
  /\ ABlocked
  /\ HRot("A", seen["A"], FALSE)
  /\ UNCHANGED <<hrot, w2n, opt>>

\* W2 rotates read: n above every epoch, genuine or junk, any boxes, any clock
W2Rot ==
  /\ w2n < W2Max
  /\ \E key \in W2Keys, ts \in 1..MaxTs :
       /\ \A i \in Ids : cm[i].by = "W2" => cm[i].ts # ts
       /\ NewCommit(Rec("rot", "W2", MaxN(Ids) + 1, key[1], ts, key[2], Current(Ids),
                        FALSE, Removed, Ids, 0, 0), "")
  /\ w2n' = w2n + 1
  /\ UNCHANGED <<hrot, opt>>

AStepC == NewCommit(Rec("step", "A", 0, TRUE, MaxTsIn(seen["A"]) + 1, {}, {}, FALSE,
                        Knows(seen["A"]), seen["A"], ANewest,
                        ReadF(seen["A"])), "A")

AStep ==
  /\ ADue /\ ~ABlocked
  /\ AStepC
  /\ UNCHANGED <<hrot, w2n, opt>>

AStepOpt ==
  /\ opt < OptSteps /\ ~ADue /\ ~ABlocked
  /\ AStepC
  /\ opt' = opt + 1
  /\ UNCHANGED <<hrot, w2n>>

Recv(v) ==
  /\ \E i \in Ids \ seen[v] : seen' = [seen EXCEPT ![v] = @ \cup {i}]
  /\ UNCHANGED <<cm, hrot, w2n, opt>>

Next ==
  \/ \E a \in Honest : HonestRot(a)
  \/ ARotDue \/ W2Rot \/ AStep \/ AStepOpt
  \/ \E v \in Viewers : Recv(v)

Fair ==
  /\ WF_vars(ARotDue) /\ WF_vars(AStep)
  /\ \A v \in Viewers : WF_vars(Recv(v))

Spec == Init /\ [][Next]_vars
LiveSpec == Spec /\ Fair

OKey == SealKey(seen["O"])
\* knowing honest rotations O holds
KnowingAtO == {i \in Rots(seen["O"]) : cm[i].knows /\ cm[i].by \in Honest}
RHolds(k) == k.gen /\ "R" \in cm[k.ep].boxed
HonestOpens(k) == k.gen /\ (cm[k.ep].boxed \cap Honest # {} \/ ("R" \in cm[k.ep].boxed /\ ~Removed))

\* NoSwallow (spec/crypto.md §3 Read key in force: "admin-written and derived by a holder
\* of its secret, so a writer's keyset never chooses it"; spec/sync-inbox.md §2 "so no
\* writer of T chooses the key outsiders seal to"): a fire taken now is sealed to a
\* genuine key of an epoch an honest node holds.
NoSwallow == OKey # None => HonestOpens(OKey)

\* NoLeak (spec/requirements.md Permissions: "The holder stops reading new content once a
\* party with the right to change the keys has done so knowing of the removal"): a fire
\* taken while O holds a knowing honest rotation K is sealed to no epoch R holds, unless
\* the key's commit is concurrent with K (K's maker did not hold it; spec/crypto.md §4
\* Encrypting under: a keyset made without knowing a departure is sealed to).
NoLeak == OKey # None => ~(RHolds(OKey) /\ \E i \in KnowingAtO : OKey.src \in cm[i].saw)
\* ... with no concurrency exception, unless O's `read` field holds a W2 keyset
\* ordered after a knowing honest rotation O holds (W2 masking it: W2 holds the new
\* epoch and could hand R the fires anyway; not defended)
Masked == cm[ReadF(seen["O"])].by = "W2" /\ \E i \in KnowingAtO : Less(i, ReadF(seen["O"]))
NoLeakStrict == OKey # None /\ ~Masked => ~(RHolds(OKey) /\ KnowingAtO # {})
\* ... masking included
NoLeakAll == OKey # None => ~(RHolds(OKey) /\ KnowingAtO # {})

\* Delivery (spec/sync-inbox.md §2: delivery pending only while no read key is in force;
\* spec/permissions.md §3: a step is due while none is): O comes to hold, for good, a key
\* in force that an honest node opens, so every pending fire is taken.
Delivered == <>[](OKey # None /\ HonestOpens(OKey))
=============================================================================

------------------------------- MODULE FireKey --------------------------------
(* What an outsider seals a fire to (spec/crypto.md §3 Read key in force,   *)
(* spec/sync-inbox.md §2). One thing T, read role only. Actors: admin A     *)
(* (honest, the only stepper), honest writer W1, malicious writer W2,       *)
(* reader R (removed at most once, by A or W1, with the rotation the        *)
(* removal carries), outsider O holding only `keys.0`. Crypto as access: an *)
(* epoch's secret is held by those its rotation boxes; its keyset's KEM key *)
(* is genuine or junk (W2 only). W2 may also rewrite an epoch already made  *)
(* with a junk KEM key (a copy: the epoch's holders unchanged). `keys.0` is *)
(* the LWW merge of the commits a node holds: the `read` field (every       *)
(* rotation writes it; one keyset value) and the step keys (A's steps,      *)
(* carrying the read key). With Parts, A may hold a rotation's `keys.0`     *)
(* delta before the rest of its commit. Stamps order LWW fields only: (ts,  *)
(* actor); an honest commit stamps above every stamp it holds; W2 picks any *)
(* ts in 1..MaxTs (a malicious clock). Commits reach A and O in any order;  *)
(* W2 holds every commit; W1 rotates holding any set of commits that        *)
(* includes its own (its view is not kept as state: a smaller space, and    *)
(* every order of receipt). Rule: "vouch" the spec (A's read key is the     *)
(* epoch of the `read` field it holds, where A holds that epoch current,    *)
(* else none; in force while the `read` field is of its epoch; none in      *)
(* force: pending); "seen" the step names the field's epoch and carries A's *)
(* newest held epoch (negative control, F3); "stamps" A's newest held epoch *)
(* while the `read` field's stamp is no later than the step's (negative     *)
(* control, F1); "newest" seal to the `read` field's keyset (negative       *)
(* control); "nopend" seal to the step's read key whatever the `read` field *)
(* holds (negative control). Fires: the sender reseals to the key in force  *)
(* whenever it changes before a peer takes it, and a peer may take it in    *)
(* any state, so a fire is not state: the invariants judge the key O would  *)
(* seal to in every state, the liveness properties what O comes to seal to  *)
(* for good. A steps when due (no read key in force, for "vouch" where A    *)
(* vouches for the field's epoch; or, unless ReadOnly, it holds a read      *)
(* epoch newer than its head registers), never while read is blocked at it  *)
(* (it knows R's removal and a current epoch does not cover it: it rotates  *)
(* first, ARotDue), and up to OptSteps times unprompted (MAY, spec/sync-    *)
(* ids.md §6 Steps). W2 never boxes R: a writer handing R a secret is a     *)
(* leak by hand, outside any key rule (threat model: writers bounded, not   *)
(* prevented).                                                              *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Rule,     \* "vouch" | "seen" | "stamps" | "newest" | "nopend"
          Parts,    \* A may hold a rotation's `keys.0` delta before its boxes
          ReadOnly, \* an honest rotation rotates read alone (no sync epoch to step for)
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

\* An epoch is named by the id of the rotation commit that made it. ep: the epoch a
\* `read` field write holds (its own id for a rotation, set by NewCommit;
\* the epoch it copies for a copy). reg, ks: a step's registered epoch and `seen`
\* epoch (rule "seen"); rk: its read key's epoch (rule "vouch", 0: none); kw: the `read`
\* field write its issuer held (not on the wire: for Masked).
Rec(k, by, n, gen, ts, boxed, sup, rm, knows, saw, reg, ks) ==
  [k |-> k, by |-> by, n |-> n, gen |-> gen, ts |-> ts, boxed |-> boxed,
   sup |-> sup, rm |-> rm, knows |-> knows, saw |-> saw, reg |-> reg, ks |-> ks, ep |-> 0, kw |-> 0, rk |-> 0]

\* the minting commit: epoch 1 boxed to everyone, and its step keys (one stamp)
Init0 == << [Rec("rot", "A", 0, TRUE, 0, {"A", "W1", "W2", "R"}, {}, FALSE, FALSE, {}, 0, 0) EXCEPT !.ep = 1],
            [Rec("step", "A", 0, TRUE, 0, {}, {}, FALSE, FALSE, {1}, 1, 1) EXCEPT !.kw = 1, !.rk = 1] >>

VARIABLES cm,     \* commit id -> commit
          seen,   \* viewer -> ids it holds
          part,   \* rotations whose `keys.0` delta A holds without its boxes
          hrot, w2n, opt

vars == <<cm, seen, part, hrot, w2n, opt>>

Ids == 1..Len(cm)
Less(i, j) == cm[i].ts < cm[j].ts \/ (cm[i].ts = cm[j].ts /\ Rank[cm[i].by] < Rank[cm[j].by])
Last(S) == CHOOSE i \in S : \A j \in S : ~Less(i, j)
Rots(S) == {i \in S : cm[i].k = "rot"}
\* writes of the `read` field: rotations and W2's copies
ReadWs(S) == {i \in S : cm[i].k \in {"rot", "copy"}}
StepsIn(S) == {i \in S : cm[i].k = "step"}
ReadF(S) == Last(ReadWs(S))
StepF(S) == Last(StepsIn(S))
MaxTsIn(S) == LET m == CHOOSE i \in S : \A j \in S : cm[j].ts <= cm[i].ts IN cm[m].ts
MaxN(S) == LET m == CHOOSE i \in Rots(S) : \A j \in Rots(S) : cm[j].n <= cm[i].n IN cm[m].n
Current(S) == Rots(S) \ UNION {cm[i].sup : i \in Rots(S)}
Removed == \E i \in Ids : cm[i].rm
Knows(S) == \E i \in S : cm[i].rm

None == [ep |-> 0, gen |-> FALSE, src |-> 0]
StepKey(s) == [ep |-> IF Rule = "vouch" THEN cm[s].rk ELSE cm[s].reg, gen |-> TRUE, src |-> s]
FieldKey(r) == [ep |-> cm[r].ep, gen |-> cm[r].gen, src |-> r]
\* the read key in force at a node holding S (spec/crypto.md §3)
InForce(S) ==
  IF Rule = "stamps" THEN IF ~Less(StepF(S), ReadF(S)) THEN StepKey(StepF(S)) ELSE None
  ELSE IF Rule = "vouch" THEN
    IF cm[StepF(S)].rk # 0 /\ cm[StepF(S)].rk = cm[ReadF(S)].ep THEN StepKey(StepF(S)) ELSE None
  ELSE IF cm[StepF(S)].ks = cm[ReadF(S)].ep THEN StepKey(StepF(S)) ELSE None
SealKey(S) ==
  CASE Rule \in {"vouch", "seen", "stamps"} -> InForce(S)
    [] Rule = "newest" -> FieldKey(ReadF(S))
    [] Rule = "nopend" -> StepKey(StepF(S))

\* A's newest read epoch it holds: greatest n, ties by lowest id
AHeld == {i \in Rots(seen["A"]) : "A" \in cm[i].boxed}
ANewest == CHOOSE i \in AHeld : \A j \in AHeld : cm[j].n < cm[i].n \/ (cm[j].n = cm[i].n /\ i <= j)
\* covering R's departure: its rotator knew of it (an epoch A lacks, by order: the same here)
ABlocked == Knows(seen["A"]) /\ \E e \in Current(seen["A"]) : ~cm[e].knows
\* the `keys.0` A holds: its commits and the rotations it holds the `keys.0` delta of
AField == seen["A"] \cup part
\* "vouch": A writes a read key only for the epoch of its `read` field, current and held
\* there (never blocked: A steps only while nothing is blocked at it)
Vouchable == LET e == cm[ReadF(AField)].ep IN e \in AHeld /\ e \in Current(seen["A"])
ADue ==
  \/ InForce(AField) = None /\ (Rule = "vouch" => Vouchable)
  \/ ~ReadOnly /\ ANewest # cm[StepF(seen["A"])].reg

Init ==
  /\ cm = Init0
  /\ seen = [v \in Viewers |-> {1, 2}]
  /\ part = {}
  /\ hrot = 0 /\ w2n = 0 /\ opt = 0

\* a rotation's epoch is its own id
NewCommit(c, v) ==
  /\ cm' = Append(cm, IF c.k = "rot" THEN [c EXCEPT !.ep = Len(cm) + 1] ELSE c)
  /\ seen' = IF v = "" THEN seen ELSE [seen EXCEPT ![v] = @ \cup {Len(cm) + 1}]
  /\ UNCHANGED part

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

\* W2 writes the `read` field again with an epoch already made, its KEM key junk
W2Copy ==
  /\ w2n < W2Max
  /\ \E e \in Rots(Ids), ts \in 1..MaxTs :
       /\ \A i \in Ids : cm[i].by = "W2" => cm[i].ts # ts
       /\ NewCommit([Rec("copy", "W2", cm[e].n, FALSE, ts, {}, {}, FALSE, FALSE, Ids, 0, 0)
                       EXCEPT !.ep = e], "")
  /\ w2n' = w2n + 1
  /\ UNCHANGED <<hrot, opt>>

AStepC == NewCommit([Rec("step", "A", 0, TRUE, MaxTsIn(AField) + 1, {}, {}, FALSE,
                         Knows(seen["A"]), seen["A"], ANewest,
                         cm[ReadF(AField)].ep)
                     EXCEPT !.kw = ReadF(AField),
                            !.rk = IF Vouchable THEN cm[ReadF(AField)].ep ELSE 0], "A")

\* "vouch": a `read` field A holds whole and cannot vouch for (junk, a lockout, a copy
\* of an epoch A lacks or holds superseded) waits for an admin's read rotation, as a
\* lockout does (notes/keys.md Lockouts: removing the writer); here A makes it, so
\* LiveSpec can assume it is made (no rule makes it due)
ARotUnv ==
  /\ Rule = "vouch" /\ ~Vouchable /\ ReadF(AField) \in seen["A"] /\ ~ABlocked
  /\ HRot("A", seen["A"], FALSE)
  /\ UNCHANGED <<hrot, w2n, opt>>

\* A takes a rotation's `keys.0` delta before its boxes (which come with Recv)
RecvPart ==
  /\ Parts
  /\ \E i \in Rots(Ids) \ AField : part' = part \cup {i}
  /\ UNCHANGED <<cm, seen, hrot, w2n, opt>>

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
  /\ UNCHANGED <<cm, part, hrot, w2n, opt>>

Next ==
  \/ \E a \in Honest : HonestRot(a)
  \/ ARotDue \/ ARotUnv \/ W2Rot \/ W2Copy \/ AStep \/ AStepOpt \/ RecvPart
  \/ \E v \in Viewers : Recv(v)

Fair ==
  /\ WF_vars(ARotDue) /\ WF_vars(ARotUnv) /\ WF_vars(AStep)
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

\* Masked: O's `read` field, or the one the issuer of O's step keys held, holds a W2
\* write ordered after a knowing honest rotation O holds (W2 masking it: W2 holds the
\* new epoch and could hand R the fires anyway; not defended). A W2 copy of an epoch
\* can name the knowing epoch at A, which then steps registering an older one, or put
\* an earlier epoch back in force with the step that named it (a rule naming the
\* keyset by its KEM key as well lets an exact copy do the same).
Masked == \E w \in {ReadF(seen["O"]), cm[StepF(seen["O"])].kw} :
            cm[w].by = "W2" /\ \E i \in KnowingAtO : Less(i, w)

\* NoLeak (spec/requirements.md Permissions: "The holder stops reading new content once a
\* party with the right to change the keys has done so knowing of the removal"): a fire
\* taken while O holds a knowing honest rotation K, unmasked, is sealed to no epoch R
\* holds, unless the key's commit is concurrent with K (neither's rotator held the other;
\* spec/crypto.md §4 Encrypting under: a keyset made without knowing a departure is
\* sealed to).
NoLeak == OKey # None /\ ~Masked =>
  ~(RHolds(OKey) /\ \E i \in KnowingAtO : OKey.src \in cm[i].saw \/ i \in cm[OKey.src].saw)
\* ... with no concurrency exception
NoLeakStrict == OKey # None /\ ~Masked => ~(RHolds(OKey) /\ KnowingAtO # {})
\* ... masking included
NoLeakAll == OKey # None => ~(RHolds(OKey) /\ KnowingAtO # {})

\* Delivery (spec/sync-inbox.md §2: delivery pending only while no read key is in force;
\* spec/permissions.md §3: a step is due while none is): O comes to hold, for good, a key
\* in force that an honest node opens, so every pending fire is taken.
Delivered == <>[](OKey # None /\ HonestOpens(OKey))

\* Healed (NoLeak's concurrency exception is a window, not a state): O comes to seal,
\* for good, to no epoch R holds once it holds a knowing honest rotation, masking aside.
Healed == <>[](OKey # None /\ ~Masked => ~(RHolds(OKey) /\ KnowingAtO # {}))
=============================================================================

---------------------------- MODULE SyncConvergence ----------------------------
(* Blob convergence of one label at one host (spec/sync.md §5-§7,              *)
(* spec/commits.md §5, history modes). A scenario module (MC.tla) fixes the    *)
(* commits. Every drop that is not purge or expiry is as covered by a valid    *)
(* snapshot; a `none` body is dropped once covered, and a writer holding one   *)
(* that is replaced owes the covering snapshot.                                *)
(* Crypto is access: a blob is [c, ds, v] = commit, delta set, encryption.     *)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Nodes, Writers,      \* Writers: stamp, upload, hold every delete token
  Commits, Snaps,      \* Snaps: compaction-snapshot commits
  DepositC,            \* commits whose author is no writer: placed by deposit
  Author, Deps,        \* Deps[c]: commits the author applied before writing c
  CD, Kills, Covers, Purges,
  Exp,                 \* Inf = absent
  KeepUntil,           \* KeepUntil[c]: keep-at-least until T (0: none)
  KeepAfter,           \* KeepAfter[c]: keep-at-least D after replaced (0: none)
  NoneC,               \* commits whose history is `none` (gone once replaced)
  PurgeKeep,           \* ROLE_KEEP: a purge commit is kept this long
  MaxT, Vs, Budget, AdvDrops, AdvReplays, Offs, Inf

\* commits §5: a commit carrying a purge request MUST NOT carry `expires`.
ASSUME \A c \in Commits : Purges[c] # {} => Exp[c] = Inf

Deltas == UNION {CD[c] : c \in Commits}
DC(d) == CHOOSE c \in Commits : d \in CD[c]
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Max(S) == CHOOSE x \in S : \A y \in S : x >= y
Blobs == [c : Commits, ds : SUBSET Deltas, v : Vs]

VARIABLES now, created, applied, held, seen, compacted, online,
          atHost, dep, stamped, tomb, adv,
          state      \* state[n]: deltas joined into n's state (crdt §4.6)
vars == <<now, created, applied, held, seen, compacted, online,
          atHost, dep, stamped, tomb, adv, state>>

-----------------------------------------------------------------------------
(* Classification of a body in a view: A = applied commits, H = held blobs   *)
(* (strict-subset rule), S = blobs whose snapshots count (coverage).         *)
KillT(A, d) == LET K == {c \in A : d \in Kills[c]}
               IN IF K = {} THEN Inf ELSE Min({created[c] : c \in K})
DeathT(A, d) == Min({KillT(A, d), Exp[DC(d)]})
Dead(A, d) == DeathT(A, d) <= now
Purged(A, d) == \E p \in A : d \in Purges[p]
\* commits §5 keep-at-least: until T, and/or until D after the earliest
\* replacing write the judging node applied (its kill time; a body nothing
\* applied kills is past it), the later; a commit carrying a purge request is
\* kept at least until ts + ROLE_KEEP whatever its mode. Judged by the
\* compactor on what it applied (A): compactors may differ.
PurgeB(c) == IF Purges[c] = {} THEN 0 ELSE created[c] + PurgeKeep
Deaths(A, b) == {KillT(A, d) : d \in {e \in b.ds : KillT(A, e) # Inf}}
AfterB(A, b) == IF KeepAfter[b.c] = 0 \/ Deaths(A, b) = {} THEN 0
                ELSE Min(Deaths(A, b)) + KeepAfter[b.c]
LeastB(A, b) == Max({KeepUntil[b.c], AfterB(A, b), PurgeB(b.c)})
Expired(b) == Exp[b.c] <= now
LiveIn(A, b) == \E d \in b.ds : ~Dead(A, d) /\ ~Purged(A, d)
\* commits §5: "A body holding no delta is covered."
CoveredBy(A, S, b) == \/ b.ds = {}
                      \/ \E s \in S : s.c \in Snaps /\ s.c # b.c /\ s.c \in A
                                     /\ b.ds \subseteq Covers[s.c]
\* sync §6 must-not-hold: purged, expired, a `none` body covered (past its
\* keep-until, commits §5: gone once replaced, at every node holding the
\* cover), or a strict subset of another held blob of the commit that is not
\* itself must-not-hold ("outside the required set" is not modeled: one label,
\* everything in the closure). The recursion reduces to BaseNot: a strict
\* superset that is a strict subset of a held blob not BaseNot has that blob
\* as a superset too.
BaseNot(A, b) ==
  \/ \E d \in b.ds : Purged(A, d)
  \/ Expired(b)
NoneGone(A, S, b) == b.c \in NoneC /\ now >= LeastB(A, b) /\ CoveredBy(A, S, b)
MustNot(A, H, b) ==
  \/ BaseNot(A, b)
  \/ NoneGone(A, H, b)
  \/ \E b2 \in H : b2.c = b.c /\ b.ds \subseteq b2.ds /\ b.ds # b2.ds /\ ~BaseNot(A, b2)
\* sync §6 must-hold: before keep-at-least or established uncovered. "A body
\* meeting a must-not-hold condition is must-not-hold whatever else holds".
MustHold(A, H, S, b) == ~MustNot(A, H, b)
                        /\ (now < LeastB(A, b) \/ ~CoveredBy(A, S, b))

NMustNot(n, b) == MustNot(applied[n], held[n], b)
NMustHold(n, b) == MustHold(applied[n], held[n], held[n], b)
SameBody(x, b) == x.c = b.c /\ x.ds = b.ds
\* sync §7: a covering snapshot under the label, as the node knows it.
SnapAt(n, b) == CoveredBy(applied[n], atHost \cap seen[n], b)
One(d) == [c |-> DC(d), ds |-> {d}, v |-> 0]
\* sync §6: the label holds a body when "a blob of the commit that is not
\* must-not-hold and holds every delta of the body that no snapshot under the
\* label covers" is there; else it lacks it. Snapshots and must-not-hold as
\* the node knows them (LHolds) or globally (GHolds). A blob must-not-hold
\* only as a strict subset has a holding superset, so BaseNot suffices.
HoldsIn(b, A, cov(_)) == \E x \in atHost : x.c = b.c /\ ~BaseNot(A, x)
                                     /\ {d \in b.ds : ~cov(One(d))} \subseteq x.ds
LHolds(n, b) == LET cov(o) == SnapAt(n, o) IN HoldsIn(b, applied[n], cov)
\* sync §7: other entries carry each live write of b: "a snapshot under the
\* label covering it, or another blob of the commit holding it that is not
\* must-not-hold and not an identical body with a higher blob ID" (v stands
\* for the blob ID order).
\* InBlob over S: the label's entries as n knows them, or n's held blobs.
LiveOf(A, b) == {d \in b.ds : ~Dead(A, d) /\ ~Purged(A, d)}
InBlob(n, b, d, S) == \E x \in S : x.c = b.c /\ d \in x.ds /\ x # b /\ ~NMustNot(n, x)
                                 /\ ~(x.ds = b.ds /\ x.v > b.v)
Carrier(n, b) == \A d \in LiveOf(applied[n], b) :
                   SnapAt(n, One(d)) \/ InBlob(n, b, d, atHost \cap seen[n])
\* commits §5 history `none`: a writer holding a `none` body that is replaced
\* (a write of it dead) and no covering snapshot owes the cover.
Replaced(A, b) == \E d \in b.ds : Dead(A, d)
OwesCover(n, b) ==
  /\ n \in Writers /\ b.c \in NoneC /\ b.c \in applied[n] /\ Replaced(applied[n], b)
  /\ ~CoveredBy(applied[n], held[n], b)
DupHigherSeen(n, b) == \E x \in atHost \cap seen[n] : SameBody(x, b) /\ x.v < b.v
Fresh(b) == {[b EXCEPT !.v = w] : w \in {u \in Vs : [b EXCEPT !.v = u] \notin tomb}}

-----------------------------------------------------------------------------
Init ==
  /\ now = 0
  /\ created = [c \in Commits |-> Inf]
  /\ applied = [n \in Nodes |-> {}]
  /\ held = [n \in Nodes |-> {}]
  /\ seen = [n \in Nodes |-> {}]
  /\ compacted = [n \in Nodes |-> {}]
  /\ online = [n \in Nodes |-> TRUE]
  /\ atHost = {} /\ dep = {} /\ stamped = {} /\ tomb = {}
  /\ adv = [drop |-> 0, replay |-> 0, off |-> 0]
  /\ state = [n \in Nodes |-> {}]

Tick == now < MaxT /\ now' = now + 1
        /\ UNCHANGED <<state, created, applied, held, seen, compacted, online,
                       atHost, dep, stamped, tomb, adv>>

\* A write. commits §5: a snapshot covers a body only if its frontier reaches
\* the body's counters, so its author has applied every commit whose deltas
\* it covers.
Write(n, c) ==
  /\ online[n] /\ Author[c] = n /\ created[c] = Inf /\ Deps[c] \subseteq applied[n]
  /\ \A d \in Covers[c] : DC(d) \in applied[n]
  /\ now < Exp[c]   \* commits §6 T > ts
  /\ created' = [created EXCEPT ![c] = now]
  /\ applied' = [applied EXCEPT ![n] = @ \cup {c}]
  /\ state' = [state EXCEPT ![n] = @ \cup CD[c] \cup Covers[c]]
  /\ held' = [held EXCEPT ![n] = @ \cup {[c |-> c, ds |-> CD[c], v |-> 0]}]
  /\ UNCHANGED <<now, seen, compacted, online, atHost, dep, stamped, tomb, adv>>

\* Cursor sync delivers each log entry once, in any order (reordering host).
Recv(n, b) ==
  /\ online[n] /\ b \in atHost /\ b \notin seen[n]
  /\ seen' = [seen EXCEPT ![n] = @ \cup {b}]
  /\ held' = [held EXCEPT ![n] = @ \cup {b}]
  /\ applied' = [applied EXCEPT ![n] = @ \cup {b.c}]
  /\ state' = [state EXCEPT ![n] = @ \cup b.ds \cup (IF b.c \in Snaps THEN Covers[b.c] ELSE {})]
  /\ UNCHANGED <<now, created, compacted, online, atHost, dep, stamped, tomb, adv>>

\* Local drop of a must-not-hold body; "a node dropping a body for a purge
\* keeps the commit as a blob without the purged deltas" (commits §5). A body
\* with live writes goes only as covered (NoneGone) or purged (its rewrite
\* carries them): nothing leaves the state uncarried.
Drop(n, b) ==
  /\ b \in held[n] /\ NMustNot(n, b)
  /\ LET keep == {d \in b.ds : ~Purged(applied[n], d)}
         rw == [c |-> b.c, ds |-> keep, v |-> 0]
     IN IF keep # b.ds /\ ~Expired(b)
           /\ ~\E x \in held[n] : SameBody(x, rw)
        THEN held' = [held EXCEPT ![n] = (@ \ {b}) \cup {rw}]
        ELSE held' = [held EXCEPT ![n] = @ \ {b}]
  /\ UNCHANGED <<state, now, created, applied, seen, compacted, online, atHost, dep, stamped, tomb, adv>>

\* sync §6: a writer uploads every must-hold body the label lacks, as a fresh
\* encryption if the old blob ID is tombstoned. Upload clears deposited (§5).
Upload(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in held[n] /\ NMustHold(n, b) /\ ~LHolds(n, b)
  /\ \E b2 \in Fresh(b) :
       /\ (b \notin tomb => b2 = b)
       /\ held' = [held EXCEPT ![n] = (@ \ {b}) \cup {b2}]
       /\ atHost' = atHost \cup {b2}
       /\ seen' = [seen EXCEPT ![n] = @ \cup {b2}]
       /\ stamped' = stamped \cup {b2}
  /\ UNCHANGED <<state, now, created, applied, compacted, online, dep, tomb, adv>>

\* sync §6: "a reader relays the stamped must-hold entries it holds that the
\* label lacks". Refused at a tombstone.
Relay(n, b) ==
  /\ online[n] /\ n \notin Writers /\ b \in held[n] /\ b \in stamped
  /\ b \notin tomb /\ ~LHolds(n, b) /\ NMustHold(n, b)
  /\ atHost' = atHost \cup {b}
  /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, dep, stamped, tomb, adv>>

\* sync §5 deposit: no stamp, flagged, refused when the budget is full.
Deposit(n, b) ==
  /\ online[n] /\ n \notin Writers /\ b \in held[n] /\ b.c \in DepositC
  /\ b \notin stamped /\ NMustHold(n, b) /\ ~LHolds(n, b) /\ Cardinality(dep) < Budget
  /\ \E b2 \in Fresh(b) :
       /\ (b \notin tomb => b2 = b)
       /\ held' = [held EXCEPT ![n] = (@ \ {b}) \cup {b2}]
       /\ atHost' = atHost \cup {b2}
       /\ dep' = dep \cup {b2}
       /\ seen' = [seen EXCEPT ![n] = @ \cup {b2}]
  /\ UNCHANGED <<state, now, created, applied, compacted, online, stamped, tomb, adv>>

\* sync §5: a writer that verifies a deposited commit the label must hold
\* re-uploads it stamped.
Promote(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in atHost \cap dep /\ b \in seen[n]
  /\ NMustHold(n, b)
  /\ dep' = dep \ {b} /\ stamped' = stamped \cup {b}
  /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, atHost, tomb, adv>>

Remove(B, tombed) ==
  /\ atHost' = atHost \ B
  /\ dep' = dep \ B
  /\ tomb' = IF tombed THEN tomb \cup B ELSE tomb
  /\ seen' = [m \in Nodes |-> seen[m] \ B]   \* re-adding is a new log event

\* sync §6/§7: token holders delete must-not-hold bodies; of two blobs with
\* the same delta set the higher ID goes; a body with live writes only while
\* another entry under the label carries them.
DupHigher(b) == \E x \in atHost : SameBody(x, b) /\ x.v < b.v
Delete(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in atHost \cap seen[n] /\ b.c \in applied[n]
  /\ NMustNot(n, b) \/ DupHigherSeen(n, b)
  /\ Carrier(n, b)
  /\ Remove({b}, TRUE)
  /\ UNCHANGED <<state, now, created, applied, held, compacted, online, stamped, adv>>

\* sync §7 compaction: drop, and delete at the host, a covered body past
\* keep-at-least, once per body (commit and delta set, sync §6). Optional,
\* so unfair.
Compact(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in held[n] \cup (atHost \cap seen[n])
  /\ b.c \in applied[n] /\ <<b.c, b.ds>> \notin compacted[n]
  /\ ~NMustNot(n, b) /\ ~NMustHold(n, b) /\ SnapAt(n, b)
  /\ held' = [held EXCEPT ![n] = {x \in @ : ~SameBody(x, b)}]
  /\ compacted' = [compacted EXCEPT ![n] = @ \cup {<<b.c, b.ds>>}]
  /\ Remove({x \in atHost : SameBody(x, b)}, TRUE)
  /\ UNCHANGED <<state, now, created, applied, online, stamped, adv>>

ExpireAt(b) == /\ b \in atHost /\ Expired(b) /\ Remove({b}, FALSE)
               /\ UNCHANGED <<state, now, created, applied, held, compacted, online, stamped, adv>>
TombGC(b) == /\ b \in tomb /\ tomb' = tomb \ {b}
             /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, atHost, dep, stamped, adv>>

GoOff(n) == /\ online[n] /\ adv.off < Offs
            /\ online' = [online EXCEPT ![n] = FALSE] /\ adv' = [adv EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, atHost, dep, stamped, tomb>>
GoOn(n) == /\ ~online[n] /\ online' = [online EXCEPT ![n] = TRUE]
           /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, atHost, dep, stamped, tomb, adv>>

\* Adversarial host: loses an entry; replays a stale stamped entry.
AdvDrop(b) == /\ b \in atHost /\ adv.drop < AdvDrops
              /\ atHost' = atHost \ {b} /\ dep' = dep \ {b} /\ adv' = [adv EXCEPT !.drop = @ + 1]
              /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, stamped, tomb>>
AdvReplay(b) == /\ b \in stamped /\ b \notin atHost /\ b \notin tomb /\ ~Expired(b)
                /\ adv.replay < AdvReplays
                /\ atHost' = atHost \cup {b} /\ adv' = [adv EXCEPT !.replay = @ + 1]
                /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, dep, stamped, tomb>>

\* Snapshot writes are optional (unfair) except when due: sync §7 "a right
\* holder that must delete a body with live writes and finds no such entry
\* uploads a covering snapshot first when it may write the aspect" (none while
\* it holds a blob that will carry them, its rewrite); commits §5 history
\* `none`: a writer holding a replaced `none` body with no cover owes one;
\* "A writer that, after applying [a purge], holds no covering snapshot of the
\* aspect under a label it writes re-snapshots there".
SnapDue(n, s) ==
  /\ n \in Writers
  /\ \/ \E b \in atHost \cap seen[n] :
          /\ b.c \in applied[n] /\ NMustNot(n, b) /\ b.ds \subseteq Covers[s]
          /\ \E d \in LiveOf(applied[n], b) :
               ~SnapAt(n, One(d)) /\ ~InBlob(n, b, d, (atHost \cap seen[n]) \cup held[n])
     \/ \E b \in held[n] : OwesCover(n, b) /\ b.ds \subseteq Covers[s]
     \/ \E p \in applied[n] :
          /\ Purges[p] # {}
          /\ ~\E x \in held[n] \cap atHost : x.c \in Snaps /\ CD[p] \subseteq Covers[x.c]

Node(n) ==
  \/ \E c \in Commits : Write(n, c)
  \/ \E b \in atHost : Recv(n, b) \/ Promote(n, b) \/ Delete(n, b)
  \/ \E b \in held[n] : Drop(n, b) \/ Upload(n, b) \/ Relay(n, b) \/ Deposit(n, b)
  \/ \E b \in held[n] \cup atHost : Compact(n, b)
  \/ GoOn(n)

Host == \E b \in atHost \cup tomb : ExpireAt(b) \/ TombGC(b)
Adversary == \/ \E n \in Nodes : GoOff(n)
             \/ \E b \in atHost : AdvDrop(b)
             \/ \E b \in stamped : AdvReplay(b)

Next == Tick \/ (\E n \in Nodes : Node(n)) \/ Host \/ Adversary

\* Weak fairness of every honest step kind per node and commit; compaction,
\* snapshots that are not due, and the adversary are unfair.
Fairness ==
  /\ WF_vars(Tick)
  /\ \A n \in Nodes :
       /\ WF_vars(\E c \in Commits \ Snaps : Write(n, c))
       /\ WF_vars(\E s \in Snaps : SnapDue(n, s) /\ Write(n, s))
       /\ WF_vars(GoOn(n))
       /\ \A c \in Commits :
            /\ WF_vars(\E b \in atHost : b.c = c /\ Recv(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Drop(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Upload(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Relay(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Deposit(n, b))
            /\ WF_vars(\E b \in atHost : b.c = c /\ Promote(n, b))
            /\ WF_vars(\E b \in atHost : b.c = c /\ Delete(n, b))
  /\ \A c \in Commits :
       /\ WF_vars(\E b \in atHost : b.c = c /\ ExpireAt(b))
       /\ WF_vars(\E b \in tomb : b.c = c /\ TombGC(b))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties. Global view: everything written, snapshots at the host.         *)
GA == {c \in Commits : created[c] # Inf}
CurBody(c) == [c |-> c, ds |-> {d \in CD[c] : ~Purged(GA, d)}, v |-> 0]
GLive(d) == DC(d) \in GA /\ ~Dead(GA, d) /\ ~Purged(GA, d)
GHolds(b) == LET cov(o) == CoveredBy(GA, atHost, o) IN HoldsIn(b, GA, cov)
Carried(S, A, d) == (\E b \in S : d \in b.ds) \/ CoveredBy(A, S, One(d))

TypeOK == /\ now \in 0..MaxT
          /\ atHost \subseteq Blobs /\ tomb \subseteq Blobs /\ dep \subseteq atHost
          /\ \A n \in Nodes : held[n] \subseteq Blobs /\ applied[n] \subseteq GA

\* sync §7 "A body with live writes ... is deleted at a label only while other
\* entries under it carry each of them": no honest step removes the last
\* host copy of a live write that reached it (checked with AdvDrops = 0).
NoLiveLoss == \A d \in Deltas :
  (GLive(d) /\ \E b \in stamped \cup dep : d \in b.ds) => Carried(atHost, GA, d)

\* every live write is in some node's state or carried at the host (true by
\* construction: nothing evicts state).
LiveKept == \A d \in Deltas :
  GLive(d) => (\E n \in Nodes : d \in state[n]) \/ Carried(atHost, GA, d)
\* crdt §4.6, commits §5: a node's state is the join of the bodies it holds:
\* every live write in its state is carried by a body or snapshot it holds,
\* at all times (no drop leaves a write in the state alone).
StateCarried == \A n \in Nodes, d \in Deltas :
  (d \in state[n] /\ DC(d) \in applied[n] /\ ~Dead(applied[n], d) /\ ~Purged(applied[n], d))
    => Carried(held[n], applied[n], d)
\* commits §5 keep-at-least: before its bound (judged on everything written)
\* a body leaves a node or the host only by purge or expiry: a node that
\* applied a kept commit holds a blob of it, and one that reached the host
\* stays there.
KeptUntil == \A c \in GA : now < LeastB(GA, CurBody(c)) /\ Exp[c] > now /\ CD[c] \cap UNION {Purges[p] : p \in GA} = {} =>
  /\ \A n \in Nodes : c \in applied[n] => \E b \in held[n] : b.c = c
  /\ (\E b \in stamped \cup dep : b.c = c) => \E b \in atHost : b.c = c
\* commits §5 history `none`: no writer ends up holding a replaced `none`
\* body uncovered.
NoneCovered == <>[](\A n \in Nodes : \A b \in held[n] : ~OwesCover(n, b))

\* sync §6 convergence: the label ends up holding every must-hold body.
Converge == <>[](\A c \in GA :
  MustHold(GA, {}, atHost, CurBody(c)) => GHolds(CurBody(c)))
\* sync §6: must-not-hold bodies (purged, expired, covered `none`, strict
\* subsets, §7 duplicates) do not persist at the host.
Clean == <>[](\A b \in atHost : ~MustNot(GA, atHost, b) /\ ~DupHigher(b))
\* No infinite upload/delete alternation: the host's entries settle.
Quiesce == <>[][atHost' = atHost]_vars
\* sync §5: a deposited commit the label must hold is eventually stamped.
Promoted == <>[](\A b \in dep : ~MustHold(GA, {}, atHost, b))
\* commits §5 "Every node applying it drops ... every body carrying their
\* values": every node eventually holds no purged body.
PurgeReachesAll == <>[](\A n \in Nodes : \A b \in held[n] : \A d \in b.ds : ~Purged(GA, d))
=============================================================================

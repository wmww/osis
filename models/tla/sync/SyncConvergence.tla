---------------------------- MODULE SyncConvergence ----------------------------
(* Blob convergence of one label at one blind server (spec/sync.md §5-§7,      *)
(* spec/commits.md §5). A scenario module (MC_*.tla) fixes the commits.        *)
(* Crypto is access: a blob is [c, ds, v] = commit, delta set, encryption.     *)
EXTENDS Naturals, FiniteSets

CONSTANTS
  Nodes, Writers,      \* Writers: stamp, upload, hold every delete token
  Commits, Snaps,      \* Snaps: compaction-snapshot commits
  DepositC,            \* commits whose author is no writer: placed by deposit
  Author, Deps,        \* Deps[c]: commits the author applied before writing c
  CD, Kills, Covers, Purges,
  Exp, LeastAbs, LeastRel, MostAbs, MostRel,  \* Inf = absent
  PurgeKeep,           \* MEMBERSHIP_KEEP: a purge commit is kept this long
  MaxT, Vs, Budget, AdvDrops, AdvReplays, Offs, Inf

\* commits §5: a commit carrying a purge request MUST NOT carry `expires`.
ASSUME \A c \in Commits : Purges[c] # {} => Exp[c] = Inf

Deltas == UNION {CD[c] : c \in Commits}
DC(d) == CHOOSE c \in Commits : d \in CD[c]
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Max(S) == CHOOSE x \in S : \A y \in S : x >= y
Blobs == [c : Commits, ds : SUBSET Deltas, v : Vs]

VARIABLES now, created, applied, held, seen, compacted, online,
          srv, dep, stamped, tomb, timed, adv,
          state      \* state[n]: deltas joined into n's state (crdt §4.6)
vars == <<now, created, applied, held, seen, compacted, online,
          srv, dep, stamped, tomb, timed, adv, state>>

-----------------------------------------------------------------------------
(* Classification of a body in a view: A = applied commits, H = held blobs   *)
(* (strict-subset rule), S = blobs whose snapshots count (coverage).         *)
KillT(A, d) == LET K == {c \in A : d \in Kills[c]}
               IN IF K = {} THEN Inf ELSE Min({created[c] : c \in K})
DeathT(A, d) == Min({KillT(A, d), Exp[DC(d)]})
Dead(A, d) == DeathT(A, d) <= now
Purged(A, d) == \E p \in A : d \in Purges[p]
Deaths(A, b) == {DeathT(A, d) : d \in {e \in b.ds : Dead(A, e)}}
\* commits §5: the later bound counts for at least, the earlier for at most;
\* a body with no dead writes is past a relative at-least bound.
\* commits §5: a commit carrying a purge request is kept at least until ts +
\* MEMBERSHIP_KEEP, whatever its deltas' bounds (so it beats keep-at-most).
PurgeB(c) == IF Purges[c] = {} THEN 0 ELSE created[c] + PurgeKeep
LeastB(A, b) == Max({IF LeastRel[b.c] = Inf \/ Deaths(A, b) = {} THEN 0
                     ELSE Max(Deaths(A, b)) + LeastRel[b.c],
                     IF LeastAbs[b.c] = Inf THEN 0 ELSE LeastAbs[b.c],
                     PurgeB(b.c)})
MostB(A, b) == Max({PurgeB(b.c),
                    Min({IF MostRel[b.c] = Inf \/ Deaths(A, b) = {} THEN Inf
                         ELSE Min(Deaths(A, b)) + MostRel[b.c], MostAbs[b.c]})})
Expired(b) == Exp[b.c] <= now
LiveIn(A, b) == \E d \in b.ds : ~Dead(A, d) /\ ~Purged(A, d)
\* commits §5: "A body holding no delta is covered."
CoveredBy(A, S, b) == \/ b.ds = {}
                      \/ \E s \in S : s.c \in Snaps /\ s.c # b.c /\ s.c \in A
                                     /\ b.ds \subseteq Covers[s.c]
\* sync §6 must-not-hold: purged, expired, past keep-at-most, or a strict
\* subset of another held blob of the commit that is not itself must-not-hold
\* ("outside the required set" is not modeled: one label, everything in the
\* closure). The recursion reduces to BaseNot: a strict superset that is a
\* strict subset of a held blob not BaseNot has that blob as a superset too.
BaseNot(A, b) ==
  \/ \E d \in b.ds : Purged(A, d)
  \/ Expired(b)
  \/ now >= MostB(A, b)
MustNot(A, H, b) ==
  \/ BaseNot(A, b)
  \/ \E b2 \in H : b2.c = b.c /\ b.ds \subseteq b2.ds /\ b.ds # b2.ds /\ ~BaseNot(A, b2)
\* sync §6 must-hold: before keep-at-least or established uncovered. "A body
\* meeting a must-not-hold condition is must-not-hold whatever else holds".
MustHold(A, H, S, b) == ~MustNot(A, H, b)
                        /\ (now < LeastB(A, b) \/ ~CoveredBy(A, S, b))

NMustNot(n, b) == MustNot(applied[n], held[n], b)
NMustHold(n, b) == MustHold(applied[n], held[n], held[n], b)
SameBody(x, b) == x.c = b.c /\ x.ds = b.ds
\* sync §7: a covering snapshot under the label, as the node knows it.
SnapAt(n, b) == CoveredBy(applied[n], srv \cap seen[n], b)
One(d) == [c |-> DC(d), ds |-> {d}, v |-> 0]
\* sync §6: the label holds a body when "a blob of the commit that is not
\* must-not-hold and holds every delta of the body that no snapshot under the
\* label covers" is there; else it lacks it. Snapshots and must-not-hold as
\* the node knows them (LHolds) or globally (GHolds). A blob must-not-hold
\* only as a strict subset has a holding superset, so BaseNot suffices.
HoldsIn(b, A, cov(_)) == \E x \in srv : x.c = b.c /\ ~BaseNot(A, x)
                                     /\ {d \in b.ds : ~cov(One(d))} \subseteq x.ds
LHolds(n, b) == LET cov(o) == SnapAt(n, o) IN HoldsIn(b, applied[n], cov)
\* sync §7: "another entry under it carries them: a covering snapshot, a blob
\* of the commit holding a superset of its deltas, or an identical body with
\* a lower blob ID" (v stands for the blob ID order).
Carrier(n, b) == \/ SnapAt(n, b)
                 \/ \E x \in srv \cap seen[n] :
                      /\ x.c = b.c
                      /\ \/ b.ds \subseteq x.ds /\ b.ds # x.ds
                         \/ x.ds = b.ds /\ x.v < b.v
\* commits §5: "A node that may write the aspect and holds no snapshot
\* covering a body with live writes writes one before dropping the body"
\* (read as: a drop past keep-at-most; AMBIGUITIES.md S16).
NeedsSnapToDrop(n, b) ==
  /\ n \in Writers /\ LiveIn(applied[n], b) /\ now >= MostB(applied[n], b)
  /\ ~CoveredBy(applied[n], held[n], b)
\* commits §5 at most D after replaced: the replacing node (it applied its
\* own commit killing a write of b) sends the timed delete, "after the
\* snapshot of sync §7 when the body still has live writes".
Replacer(n, b) == \E c \in applied[n] : Author[c] = n /\ b.ds \cap Kills[c] # {}
TimedDue(n, b) ==
  /\ n \in Writers /\ b \in srv \cap seen[n] /\ MostRel[b.c] # Inf /\ Replacer(n, b)
  /\ ~\E e \in timed : e[1] = b
DupHigherSeen(n, b) == \E x \in srv \cap seen[n] : SameBody(x, b) /\ x.v < b.v
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
  /\ srv = {} /\ dep = {} /\ stamped = {} /\ tomb = {} /\ timed = {}
  /\ adv = [drop |-> 0, replay |-> 0, off |-> 0]
  /\ state = [n \in Nodes |-> {}]

Tick == now < MaxT /\ now' = now + 1
        /\ UNCHANGED <<state, created, applied, held, seen, compacted, online,
                       srv, dep, stamped, tomb, timed, adv>>

\* A write. The timed delete of a body it replaces is SendTimed. commits §5: a
\* snapshot covers a body only if its frontier reaches the body's counters,
\* so its author has applied every commit whose deltas it covers.
Write(n, c) ==
  /\ online[n] /\ Author[c] = n /\ created[c] = Inf /\ Deps[c] \subseteq applied[n]
  /\ \A d \in Covers[c] : DC(d) \in applied[n]
  /\ now < Exp[c] /\ now < MostAbs[c]   \* commits §6 T > ts; same for at-most
  /\ created' = [created EXCEPT ![c] = now]
  /\ applied' = [applied EXCEPT ![n] = @ \cup {c}]
  /\ state' = [state EXCEPT ![n] = @ \cup CD[c] \cup Covers[c]]
  /\ held' = [held EXCEPT ![n] = @ \cup {[c |-> c, ds |-> CD[c], v |-> 0]}]
  /\ UNCHANGED <<now, seen, compacted, online, srv, dep, stamped, tomb, timed, adv>>

\* commits §5 / sync §5: the replacing writer sends the server a delete timed
\* at the bound (first death plus D), with a covering snapshot already under
\* the label when the body still has live writes.
SendTimed(n, b) ==
  /\ online[n] /\ TimedDue(n, b)
  /\ LiveIn(applied[n], b) => SnapAt(n, b)
  /\ timed' = timed \cup {<<b, Min(Deaths(applied[n], b)) + MostRel[b.c]>>}
  /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, srv, dep,
                 stamped, tomb, adv>>

\* Cursor sync delivers each log entry once, in any order (reordering server).
Recv(n, b) ==
  /\ online[n] /\ b \in srv /\ b \notin seen[n]
  /\ seen' = [seen EXCEPT ![n] = @ \cup {b}]
  /\ held' = [held EXCEPT ![n] = @ \cup {b}]
  /\ applied' = [applied EXCEPT ![n] = @ \cup {b.c}]
  /\ state' = [state EXCEPT ![n] = @ \cup b.ds \cup (IF b.c \in Snaps THEN Covers[b.c] ELSE {})]
  /\ UNCHANGED <<now, created, compacted, online, srv, dep, stamped, tomb, timed, adv>>

\* Local drop of a must-not-hold body; "a node dropping a body for a purge
\* keeps the commit as a blob without the purged deltas" (commits §5); a
\* writer dropping a body with live writes first holds a covering snapshot.
Drop(n, b) ==
  /\ b \in held[n] /\ NMustNot(n, b) /\ ~NeedsSnapToDrop(n, b)
  /\ LET keep == {d \in b.ds : ~Purged(applied[n], d)}
         rw == [c |-> b.c, ds |-> keep, v |-> 0]
     IN IF keep # b.ds /\ ~Expired(b)
           /\ ~\E x \in held[n] : SameBody(x, rw)
        THEN held' = [held EXCEPT ![n] = (@ \ {b}) \cup {rw}]
        ELSE held' = [held EXCEPT ![n] = @ \ {b}]
  /\ UNCHANGED <<state, now, created, applied, seen, compacted, online, srv, dep, stamped, tomb, timed, adv>>

\* sync §6: a writer uploads every must-hold body the label lacks, as a fresh
\* encryption if the old blob ID is tombstoned. Upload clears deposited (§5).
Upload(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in held[n] /\ NMustHold(n, b) /\ ~LHolds(n, b)
  /\ \E b2 \in Fresh(b) :
       /\ (b \notin tomb => b2 = b)
       /\ held' = [held EXCEPT ![n] = (@ \ {b}) \cup {b2}]
       /\ srv' = srv \cup {b2}
       /\ seen' = [seen EXCEPT ![n] = @ \cup {b2}]
       /\ stamped' = stamped \cup {b2}
  /\ UNCHANGED <<state, now, created, applied, compacted, online, dep, tomb, timed, adv>>

\* sync §6: "a reader relays the stamped must-hold entries it holds that the
\* label lacks". Refused at a tombstone.
Relay(n, b) ==
  /\ online[n] /\ n \notin Writers /\ b \in held[n] /\ b \in stamped
  /\ b \notin tomb /\ ~LHolds(n, b) /\ NMustHold(n, b)
  /\ srv' = srv \cup {b}
  /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, dep, stamped, tomb, timed, adv>>

\* sync §5 deposit: no stamp, flagged, refused when the budget is full.
Deposit(n, b) ==
  /\ online[n] /\ n \notin Writers /\ b \in held[n] /\ b.c \in DepositC
  /\ b \notin stamped /\ NMustHold(n, b) /\ ~LHolds(n, b) /\ Cardinality(dep) < Budget
  /\ \E b2 \in Fresh(b) :
       /\ (b \notin tomb => b2 = b)
       /\ held' = [held EXCEPT ![n] = (@ \ {b}) \cup {b2}]
       /\ srv' = srv \cup {b2}
       /\ dep' = dep \cup {b2}
       /\ seen' = [seen EXCEPT ![n] = @ \cup {b2}]
  /\ UNCHANGED <<state, now, created, applied, compacted, online, stamped, tomb, timed, adv>>

\* sync §5: a writer that verifies a deposited commit the label must hold
\* re-uploads it stamped.
Promote(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in srv \cap dep /\ b \in seen[n]
  /\ NMustHold(n, b)
  /\ dep' = dep \ {b} /\ stamped' = stamped \cup {b}
  /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, srv, tomb, timed, adv>>

Remove(B, tombed) ==
  /\ srv' = srv \ B
  /\ dep' = dep \ B
  /\ timed' = {e \in timed : e[1] \notin B}
  /\ tomb' = IF tombed THEN tomb \cup B ELSE tomb
  /\ seen' = [m \in Nodes |-> seen[m] \ B]   \* re-adding is a new log event

\* sync §6/§7: token holders delete must-not-hold bodies; of two blobs with
\* the same delta set the higher ID goes; a body with live writes only while
\* another entry under the label carries them.
DupHigher(b) == \E x \in srv : SameBody(x, b) /\ x.v < b.v
Delete(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in srv \cap seen[n] /\ b.c \in applied[n]
  /\ NMustNot(n, b) \/ DupHigherSeen(n, b)
  /\ LiveIn(applied[n], b) => Carrier(n, b)
  /\ Remove({b}, TRUE)
  /\ UNCHANGED <<state, now, created, applied, held, compacted, online, stamped, adv>>

\* sync §7 compaction: drop, and delete at the server, a covered body past
\* keep-at-least, once per body (commit and delta set, sync §6). Optional,
\* so unfair.
Compact(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in held[n] \cup (srv \cap seen[n])
  /\ b.c \in applied[n] /\ <<b.c, b.ds>> \notin compacted[n]
  /\ ~NMustNot(n, b) /\ ~NMustHold(n, b) /\ SnapAt(n, b)
  /\ held' = [held EXCEPT ![n] = {x \in @ : ~SameBody(x, b)}]
  /\ compacted' = [compacted EXCEPT ![n] = @ \cup {<<b.c, b.ds>>}]
  /\ Remove({x \in srv : SameBody(x, b)}, TRUE)
  /\ UNCHANGED <<state, now, created, applied, online, stamped, adv>>

TimedFire(b) == /\ b \in srv /\ \E e \in timed : e[1] = b /\ e[2] <= now
                /\ Remove({b}, TRUE)
                /\ UNCHANGED <<state, now, created, applied, held, compacted, online, stamped, adv>>
ExpireAt(b) == /\ b \in srv /\ Expired(b) /\ Remove({b}, FALSE)
               /\ UNCHANGED <<state, now, created, applied, held, compacted, online, stamped, adv>>
TombGC(b) == /\ b \in tomb /\ tomb' = tomb \ {b}
             /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, srv, dep, stamped, timed, adv>>

GoOff(n) == /\ online[n] /\ adv.off < Offs
            /\ online' = [online EXCEPT ![n] = FALSE] /\ adv' = [adv EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, srv, dep, stamped, tomb, timed>>
GoOn(n) == /\ ~online[n] /\ online' = [online EXCEPT ![n] = TRUE]
           /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, srv, dep, stamped, tomb, timed, adv>>

\* Adversarial server: loses an entry; replays a stale stamped entry.
AdvDrop(b) == /\ b \in srv /\ adv.drop < AdvDrops
              /\ srv' = srv \ {b} /\ dep' = dep \ {b} /\ adv' = [adv EXCEPT !.drop = @ + 1]
              /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, stamped, tomb, timed>>
AdvReplay(b) == /\ b \in stamped /\ b \notin srv /\ b \notin tomb /\ ~Expired(b)
                /\ adv.replay < AdvReplays
                /\ srv' = srv \cup {b} /\ adv' = [adv EXCEPT !.replay = @ + 1]
                /\ UNCHANGED <<state, now, created, applied, held, seen, compacted, online, dep, stamped, tomb, timed>>

\* Snapshot writes are optional (unfair) except when due: sync §7 "a right
\* holder that must delete a body with live writes and finds no such entry
\* uploads a covering snapshot first when it may write the aspect"; commits §5
\* "A writer that, after applying [a purge], holds no covering snapshot of the
\* aspect under a label it writes re-snapshots there"; a writer that must drop
\* a body with live writes and holds no covering snapshot (commits §5 keep at
\* most); a replacer whose timed delete waits for a snapshot (commits §5).
SnapDue(n, s) ==
  /\ n \in Writers
  /\ \/ \E b \in srv \cap seen[n] :
          /\ b.c \in applied[n] /\ NMustNot(n, b) /\ LiveIn(applied[n], b)
          /\ ~Carrier(n, b) /\ b.ds \subseteq Covers[s]
     \/ \E b \in held[n] : NeedsSnapToDrop(n, b) /\ b.ds \subseteq Covers[s]
     \/ \E b \in srv \cap seen[n] :
          /\ TimedDue(n, b) /\ LiveIn(applied[n], b) /\ ~SnapAt(n, b)
          /\ b.ds \subseteq Covers[s]
     \/ \E p \in applied[n] :
          /\ Purges[p] # {}
          /\ ~\E x \in held[n] \cap srv : x.c \in Snaps /\ CD[p] \subseteq Covers[x.c]

Node(n) ==
  \/ \E c \in Commits : Write(n, c)
  \/ \E b \in srv : Recv(n, b) \/ Promote(n, b) \/ Delete(n, b) \/ SendTimed(n, b)
  \/ \E b \in held[n] : Drop(n, b) \/ Upload(n, b) \/ Relay(n, b) \/ Deposit(n, b)
  \/ \E b \in held[n] \cup srv : Compact(n, b)
  \/ GoOn(n)

Server == \E b \in srv \cup tomb : TimedFire(b) \/ ExpireAt(b) \/ TombGC(b)
Adversary == \/ \E n \in Nodes : GoOff(n)
             \/ \E b \in srv : AdvDrop(b)
             \/ \E b \in stamped : AdvReplay(b)

Next == Tick \/ (\E n \in Nodes : Node(n)) \/ Server \/ Adversary

\* Weak fairness of every honest step kind per node and commit; compaction,
\* snapshots that are not due, and the adversary are unfair.
Fairness ==
  /\ WF_vars(Tick)
  /\ \A n \in Nodes :
       /\ WF_vars(\E c \in Commits \ Snaps : Write(n, c))
       /\ WF_vars(\E s \in Snaps : SnapDue(n, s) /\ Write(n, s))
       /\ WF_vars(GoOn(n))
       /\ \A c \in Commits :
            /\ WF_vars(\E b \in srv : b.c = c /\ Recv(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Drop(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Upload(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Relay(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Deposit(n, b))
            /\ WF_vars(\E b \in srv : b.c = c /\ Promote(n, b))
            /\ WF_vars(\E b \in srv : b.c = c /\ Delete(n, b))
            /\ WF_vars(\E b \in srv : b.c = c /\ SendTimed(n, b))
  /\ \A c \in Commits :
       /\ WF_vars(\E b \in srv : b.c = c /\ TimedFire(b))
       /\ WF_vars(\E b \in srv : b.c = c /\ ExpireAt(b))
       /\ WF_vars(\E b \in tomb : b.c = c /\ TombGC(b))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties. Global view: everything written, snapshots at the server.    *)
GA == {c \in Commits : created[c] # Inf}
CurBody(c) == [c |-> c, ds |-> {d \in CD[c] : ~Purged(GA, d)}, v |-> 0]
GLive(d) == DC(d) \in GA /\ ~Dead(GA, d) /\ ~Purged(GA, d)
GHolds(b) == LET cov(o) == CoveredBy(GA, srv, o) IN HoldsIn(b, GA, cov)
Carried(S, A, d) == (\E b \in S : d \in b.ds) \/ CoveredBy(A, S, One(d))

TypeOK == /\ now \in 0..MaxT
          /\ srv \subseteq Blobs /\ tomb \subseteq Blobs /\ dep \subseteq srv
          /\ \A n \in Nodes : held[n] \subseteq Blobs /\ applied[n] \subseteq GA

\* sync §7 "A body with live writes is deleted at a label only once a snapshot
\* covering it is under that label": no honest step removes the last server
\* copy of a live write that reached it (checked with AdvDrops = 0).
NoLiveLoss == \A d \in Deltas :
  (GLive(d) /\ \E b \in stamped \cup dep : d \in b.ds) => Carried(srv, GA, d)

\* sync §7 "Live state is never lost: a node keeps it in its own state ... and
\* a label in an entry": every live write is in some node's state or carried
\* at the server (true by construction: nothing evicts state).
LiveKept == \A d \in Deltas :
  GLive(d) => (\E n \in Nodes : d \in state[n]) \/ Carried(srv, GA, d)
\* sync §7 "a member serves current state from the bodies and snapshots it
\* holds": eventually every live write in a node's state is carried by a body
\* or snapshot it holds (in between, e.g. after a keep-at-most drop, it may not).
Serves == <>[](\A n \in Nodes, d \in Deltas :
  (d \in state[n] /\ DC(d) \in applied[n] /\ ~Dead(applied[n], d) /\ ~Purged(applied[n], d))
    => Carried(held[n], applied[n], d))

\* sync §6 convergence: the label ends up holding every must-hold body.
Converge == <>[](\A c \in GA :
  MustHold(GA, {}, srv, CurBody(c)) => GHolds(CurBody(c)))
\* sync §6: must-not-hold bodies (purged, expired, past keep-at-most, strict
\* subsets, §7 duplicates) do not persist at the server.
Clean == <>[](\A b \in srv : ~MustNot(GA, srv, b) /\ ~DupHigher(b))
\* No infinite upload/delete alternation: the server's entries settle.
Quiesce == <>[][srv' = srv]_vars
\* sync §5: a deposited commit the label must hold is eventually stamped.
Promoted == <>[](\A b \in dep : ~MustHold(GA, {}, srv, b))
\* commits §5 "Every node applying it drops ... every body carrying their
\* values": every node eventually holds no purged body.
PurgeReachesAll == <>[](\A n \in Nodes : \A b \in held[n] : \A d \in b.ds : ~Purged(GA, d))
=============================================================================

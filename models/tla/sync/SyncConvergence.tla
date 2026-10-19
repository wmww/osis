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
  MaxT, Vs, Budget, AdvDrops, AdvReplays, Offs, Inf

Deltas == UNION {CD[c] : c \in Commits}
DC(d) == CHOOSE c \in Commits : d \in CD[c]
Min(S) == CHOOSE x \in S : \A y \in S : x <= y
Max(S) == CHOOSE x \in S : \A y \in S : x >= y
Blobs == [c : Commits, ds : SUBSET Deltas, v : Vs]

VARIABLES now, created, applied, held, seen, compacted, online,
          srv, dep, stamped, tomb, timed, adv
vars == <<now, created, applied, held, seen, compacted, online,
          srv, dep, stamped, tomb, timed, adv>>

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
LeastB(A, b) == Max({IF LeastRel[b.c] = Inf \/ Deaths(A, b) = {} THEN 0
                     ELSE Max(Deaths(A, b)) + LeastRel[b.c],
                     IF LeastAbs[b.c] = Inf THEN 0 ELSE LeastAbs[b.c]})
MostB(A, b) == Min({IF MostRel[b.c] = Inf \/ Deaths(A, b) = {} THEN Inf
                    ELSE Min(Deaths(A, b)) + MostRel[b.c], MostAbs[b.c]})
Expired(b) == Exp[b.c] <= now
LiveIn(A, b) == \E d \in b.ds : ~Dead(A, d) /\ ~Purged(A, d)
CoveredBy(A, S, b) == \E s \in S : s.c \in Snaps /\ s.c # b.c /\ s.c \in A
                                   /\ b.ds \subseteq Covers[s.c]
\* sync §6 must-not-hold: purged, expired, past keep-at-most, or a strict
\* subset of another held blob of the commit ("outside the required set" is
\* not modeled: one label, everything in the closure).
MustNot(A, H, b) ==
  \/ \E d \in b.ds : Purged(A, d)
  \/ Expired(b)
  \/ now >= MostB(A, b)
  \/ \E b2 \in H : b2.c = b.c /\ b.ds \subseteq b2.ds /\ b.ds # b2.ds
\* sync §6 must-hold: before keep-at-least or established uncovered. Must-not
\* wins a conflict (AMBIGUITIES.md).
MustHold(A, H, S, b) == ~MustNot(A, H, b)
                        /\ (now < LeastB(A, b) \/ ~CoveredBy(A, S, b))

NMustNot(n, b) == MustNot(applied[n], held[n], b)
NMustHold(n, b) == MustHold(applied[n], held[n], held[n], b)
SameBody(x, b) == x.c = b.c /\ x.ds = b.ds
BodyAt(b) == \E x \in srv : SameBody(x, b)
\* sync §7: "snapshot under the label first", as the node knows it.
SnapAt(n, b) == CoveredBy(applied[n], srv \cap seen[n], b)
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

Tick == now < MaxT /\ now' = now + 1
        /\ UNCHANGED <<created, applied, held, seen, compacted, online,
                       srv, dep, stamped, tomb, timed, adv>>

\* A write. A writer replacing a body under a relative keep-at-most sends the
\* timed delete with it (commits §5, sync §5).
Write(n, c) ==
  /\ online[n] /\ Author[c] = n /\ created[c] = Inf /\ Deps[c] \subseteq applied[n]
  /\ now < Exp[c] /\ now < MostAbs[c]   \* commits §6 T > ts; same for at-most
  /\ created' = [created EXCEPT ![c] = now]
  /\ applied' = [applied EXCEPT ![n] = @ \cup {c}]
  /\ held' = [held EXCEPT ![n] = @ \cup {[c |-> c, ds |-> CD[c], v |-> 0]}]
  /\ timed' = IF n \notin Writers THEN timed ELSE timed \cup
        {<<b, now + MostRel[b.c]>> : b \in {x \in srv \cap seen[n] :
            x.ds \cap Kills[c] # {} /\ MostRel[x.c] # Inf}}
  /\ UNCHANGED <<now, seen, compacted, online, srv, dep, stamped, tomb, adv>>

\* Cursor sync delivers each log entry once, in any order (reordering server).
Recv(n, b) ==
  /\ online[n] /\ b \in srv /\ b \notin seen[n]
  /\ seen' = [seen EXCEPT ![n] = @ \cup {b}]
  /\ held' = [held EXCEPT ![n] = @ \cup {b}]
  /\ applied' = [applied EXCEPT ![n] = @ \cup {b.c}]
  /\ UNCHANGED <<now, created, compacted, online, srv, dep, stamped, tomb, timed, adv>>

\* Local drop of a must-not-hold body; a writer dropping a purged body keeps
\* the header as a rewrite without the purged deltas (commits §5).
Drop(n, b) ==
  /\ b \in held[n] /\ NMustNot(n, b)
  /\ LET keep == {d \in b.ds : ~Purged(applied[n], d)}
         rw == [c |-> b.c, ds |-> keep, v |-> 0]
     IN IF n \in Writers /\ keep # b.ds /\ ~Expired(b)
           /\ ~\E x \in held[n] : SameBody(x, rw)
        THEN held' = [held EXCEPT ![n] = (@ \ {b}) \cup {rw}]
        ELSE held' = [held EXCEPT ![n] = @ \ {b}]
  /\ UNCHANGED <<now, created, applied, seen, compacted, online, srv, dep, stamped, tomb, timed, adv>>

\* sync §6: a writer uploads every must-hold body the label lacks, as a fresh
\* encryption if the old blob ID is tombstoned. Upload clears deposited (§5).
Upload(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in held[n] /\ NMustHold(n, b) /\ ~BodyAt(b)
  /\ \E b2 \in Fresh(b) :
       /\ (b \notin tomb => b2 = b)
       /\ held' = [held EXCEPT ![n] = (@ \ {b}) \cup {b2}]
       /\ srv' = srv \cup {b2}
       /\ seen' = [seen EXCEPT ![n] = @ \cup {b2}]
       /\ stamped' = stamped \cup {b2}
  /\ UNCHANGED <<now, created, applied, compacted, online, dep, tomb, timed, adv>>

\* sync §6: a reader relays the stamped entries it holds (must-hold only:
\* "nobody acts on may-hold bodies"). Refused at a tombstone.
Relay(n, b) ==
  /\ online[n] /\ n \notin Writers /\ b \in held[n] /\ b \in stamped
  /\ b \notin tomb /\ ~BodyAt(b) /\ NMustHold(n, b)
  /\ srv' = srv \cup {b}
  /\ UNCHANGED <<now, created, applied, held, seen, compacted, online, dep, stamped, tomb, timed, adv>>

\* sync §5 deposit: no stamp, flagged, refused when the budget is full.
Deposit(n, b) ==
  /\ online[n] /\ n \notin Writers /\ b \in held[n] /\ b.c \in DepositC
  /\ b \notin stamped /\ NMustHold(n, b) /\ ~BodyAt(b) /\ Cardinality(dep) < Budget
  /\ \E b2 \in Fresh(b) :
       /\ (b \notin tomb => b2 = b)
       /\ held' = [held EXCEPT ![n] = (@ \ {b}) \cup {b2}]
       /\ srv' = srv \cup {b2}
       /\ dep' = dep \cup {b2}
       /\ seen' = [seen EXCEPT ![n] = @ \cup {b2}]
  /\ UNCHANGED <<now, created, applied, compacted, online, stamped, tomb, timed, adv>>

\* sync §5: a writer that verifies a deposited commit the label must hold
\* re-uploads it stamped.
Promote(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in srv \cap dep /\ b \in seen[n]
  /\ NMustHold(n, b)
  /\ dep' = dep \ {b} /\ stamped' = stamped \cup {b}
  /\ UNCHANGED <<now, created, applied, held, seen, compacted, online, srv, tomb, timed, adv>>

Remove(B, tombed) ==
  /\ srv' = srv \ B
  /\ dep' = dep \ B
  /\ timed' = {e \in timed : e[1] \notin B}
  /\ tomb' = IF tombed THEN tomb \cup B ELSE tomb
  /\ seen' = [m \in Nodes |-> seen[m] \ B]   \* re-adding is a new log event

\* sync §6/§7: token holders delete must-not-hold bodies; of two blobs with
\* the same delta set the higher ID goes; a body with live writes only once a
\* covering snapshot is under the label.
DupHigher(b) == \E x \in srv : SameBody(x, b) /\ x.v < b.v
Delete(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in srv \cap seen[n] /\ b.c \in applied[n]
  /\ NMustNot(n, b) \/ DupHigher(b)
  /\ LiveIn(applied[n], b) => SnapAt(n, b) \/ DupHigher(b)
  /\ Remove({b}, TRUE)
  /\ UNCHANGED <<now, created, applied, held, compacted, online, stamped, adv>>

\* sync §7 compaction: drop, and delete at the server, a covered body past
\* keep-at-least, once per body. Optional, so unfair.
Compact(n, b) ==
  /\ online[n] /\ n \in Writers /\ b \in held[n] \cup (srv \cap seen[n])
  /\ b.c \in applied[n] /\ <<b.c, b.ds>> \notin compacted[n]
  /\ ~NMustNot(n, b) /\ ~NMustHold(n, b) /\ SnapAt(n, b)
  /\ held' = [held EXCEPT ![n] = {x \in @ : ~SameBody(x, b)}]
  /\ compacted' = [compacted EXCEPT ![n] = @ \cup {<<b.c, b.ds>>}]
  /\ Remove({x \in srv : SameBody(x, b)}, TRUE)
  /\ UNCHANGED <<now, created, applied, online, stamped, adv>>

TimedFire(b) == /\ b \in srv /\ \E e \in timed : e[1] = b /\ e[2] <= now
                /\ Remove({b}, TRUE)
                /\ UNCHANGED <<now, created, applied, held, compacted, online, stamped, adv>>
ExpireAt(b) == /\ b \in srv /\ Expired(b) /\ Remove({b}, FALSE)
               /\ UNCHANGED <<now, created, applied, held, compacted, online, stamped, adv>>
TombGC(b) == /\ b \in tomb /\ tomb' = tomb \ {b}
             /\ UNCHANGED <<now, created, applied, held, seen, compacted, online, srv, dep, stamped, timed, adv>>

GoOff(n) == /\ online[n] /\ adv.off < Offs
            /\ online' = [online EXCEPT ![n] = FALSE] /\ adv' = [adv EXCEPT !.off = @ + 1]
            /\ UNCHANGED <<now, created, applied, held, seen, compacted, srv, dep, stamped, tomb, timed>>
GoOn(n) == /\ ~online[n] /\ online' = [online EXCEPT ![n] = TRUE]
           /\ UNCHANGED <<now, created, applied, held, seen, compacted, srv, dep, stamped, tomb, timed, adv>>

\* Adversarial server: loses an entry; replays a stale stamped entry.
AdvDrop(b) == /\ b \in srv /\ adv.drop < AdvDrops
              /\ srv' = srv \ {b} /\ dep' = dep \ {b} /\ adv' = [adv EXCEPT !.drop = @ + 1]
              /\ UNCHANGED <<now, created, applied, held, seen, compacted, online, stamped, tomb, timed>>
AdvReplay(b) == /\ b \in stamped /\ b \notin srv /\ b \notin tomb /\ ~Expired(b)
                /\ adv.replay < AdvReplays
                /\ srv' = srv \cup {b} /\ adv' = [adv EXCEPT !.replay = @ + 1]
                /\ UNCHANGED <<now, created, applied, held, seen, compacted, online, dep, stamped, tomb, timed>>

Node(n) ==
  \/ \E c \in Commits : Write(n, c)
  \/ \E b \in srv : Recv(n, b) \/ Promote(n, b) \/ Delete(n, b)
  \/ \E b \in held[n] : Drop(n, b) \/ Upload(n, b) \/ Relay(n, b) \/ Deposit(n, b)
  \/ \E b \in held[n] \cup srv : Compact(n, b)
  \/ GoOn(n)

Server == \E b \in srv \cup tomb : TimedFire(b) \/ ExpireAt(b) \/ TombGC(b)
Adversary == \/ \E n \in Nodes : GoOff(n)
             \/ \E b \in srv : AdvDrop(b)
             \/ \E b \in stamped : AdvReplay(b)

Next == Tick \/ (\E n \in Nodes : Node(n)) \/ Server \/ Adversary

\* Weak fairness of every honest step kind per node and commit; compaction
\* and the adversary are unfair.
Fairness ==
  /\ WF_vars(Tick)
  /\ \A n \in Nodes :
       /\ WF_vars(\E c \in Commits : Write(n, c))
       /\ WF_vars(GoOn(n))
       /\ \A c \in Commits :
            /\ WF_vars(\E b \in srv : b.c = c /\ Recv(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Drop(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Upload(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Relay(n, b))
            /\ WF_vars(\E b \in held[n] : b.c = c /\ Deposit(n, b))
            /\ WF_vars(\E b \in srv : b.c = c /\ Promote(n, b))
            /\ WF_vars(\E b \in srv : b.c = c /\ Delete(n, b))
  /\ \A c \in Commits :
       /\ WF_vars(\E b \in srv : b.c = c /\ TimedFire(b))
       /\ WF_vars(\E b \in srv : b.c = c /\ ExpireAt(b))
       /\ WF_vars(\E b \in tomb : b.c = c /\ TombGC(b))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties. Global view: everything written, snapshots at the server.    *)
GA == {c \in Commits : created[c] # Inf}
CurBody(c) == [c |-> c, ds |-> {d \in CD[c] : ~Purged(GA, d)}, v |-> 0]
GLive(d) == DC(d) \in GA /\ ~Dead(GA, d) /\ ~Purged(GA, d) /\ now < MostAbs[DC(d)]
One(d) == [c |-> DC(d), ds |-> {d}, v |-> 0]
Carried(S, A, d) == (\E b \in S : d \in b.ds) \/ CoveredBy(A, S, One(d))

TypeOK == /\ now \in 0..MaxT
          /\ srv \subseteq Blobs /\ tomb \subseteq Blobs /\ dep \subseteq srv
          /\ \A n \in Nodes : held[n] \subseteq Blobs /\ applied[n] \subseteq GA

\* sync §7 "A body with live writes is deleted at a label only once a snapshot
\* covering it is under that label": no honest step removes the last server
\* copy of a live write that reached it (checked with AdvDrops = 0).
NoLiveLoss == \A d \in Deltas :
  (GLive(d) /\ \E b \in stamped \cup dep : d \in b.ds) => Carried(srv, GA, d)

\* sync §7 "a member MUST always be able to serve current state, from bodies
\* or a snapshot".
MemberCanServe == \A n \in Nodes, d \in Deltas :
  (DC(d) \in applied[n] /\ ~Dead(applied[n], d) /\ ~Purged(applied[n], d))
    => Carried(held[n], applied[n], d)

\* sync §6 convergence: every must-hold body ends up at the server.
Converge == <>[](\A c \in GA :
  MustHold(GA, {}, srv, CurBody(c)) => BodyAt(CurBody(c)))
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

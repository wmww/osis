---- MODULE NetShared ----
(* The shared-set half of issues/net-shared-set.md: one sync ID between node
   "a" and its peer "b" (or "c", a copy of b's store). A credential is the
   sync ID's current epoch; the rule is a function of what each node holds.
   Beacons (whole and additions, generations, pending set), Hit and its tag,
   ByRole, Lost, a removal learned on one side, rotations carried through their
   event (`until`), record loss. A rule of the design is a flag. *)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Stores, MaxEp, MaxDrop, MaxRecLoss, MaxClone, MaxRot, MaxRemove, MaxGrant,
    RoleA, RoleB, EpA, EpB,         \* initial roles and epochs (0 = holds nothing of L)
    TestPending,                    \* issue: test the whole pending set, not only what is newly changed
    AckTested,                      \* acked_pos = min(the peer's ack, tested_pos): nothing passes a change untested
    TagCheck,                       \* a Hit's accept must show the peer holds the credential
    Until,                          \* a rotation's event is served before Lost
    GenBase,                        \* additions are taken only on the generation they extend
    SReconcile,                     \* the digest of S, first message of each direction of a connection: a member on one side only is closed and pending again on both
    DeclineLost,                    \* a tester declining an accepted Hit sends Lost
    ByRoleOn,                       \* a judged holder is offered by role
    LostRetest,                     \* a member lost for a reason other than a credential change is pending again in this record, on both sides
    RepTested,                      \* that re-marking lowers tested_pos with acked_pos, so an ack in flight cannot raise it back
    OfferGate,                      \* no Offer before the peer's digest is read, so this side's list precedes it
    Follow,                         \* the stream is Pushes: only a Push marked `report` is answered with a position
    PushReport,                     \* a Push carrying an `until` event is marked `report`
    CursorReport,                   \* a connection's Pull reports its cursor, repairing a report lost with a connection
    TestAtArrival,                  \* the test of a filter's arrival precedes every later message of the connection
    Hostile                         \* the peer may answer any Hit as accepted

A == "a"
Other(x, l) == CHOOSE y \in l : y # x
Rec0 == [rid |-> 0, stored |-> {}, gen |-> 0, sentGen |-> 0, ackedGen |-> 0, ackRecv |-> 0, acked |-> 0, sentPos |-> 0,
         tested |-> 0, ranPos |-> 0, ranGen |-> 0, open |-> FALSE, proof |-> "none", proofEp |-> 0,
         outst |-> FALSE, rejected |-> FALSE, sentRot |-> 0, past |-> 0, seen |-> 0, digRead |-> FALSE]
Node0(role, ep) == [ep |-> ep, view |-> "unknown", pos |-> IF ep > 0 THEN 1 ELSE 0,
                    changed |-> [c \in 1..MaxEp |-> IF c = ep THEN 1 ELSE 0], rec |-> Rec0]

VARIABLES st, role, removed, epoch, link, q, active, cloned, cnt
vars == <<st, role, removed, epoch, link, q, active, cloned, cnt>>

Init ==
    /\ st = [s \in Stores |-> IF s = A THEN Node0(RoleA, EpA) ELSE Node0(RoleB, EpB)]
    /\ role = [s \in Stores |-> IF s = A THEN RoleA ELSE RoleB]
    /\ removed = [s \in Stores |-> FALSE]
    /\ epoch = IF EpA > EpB THEN EpA ELSE EpB
    /\ link = {}
    /\ q = [s \in Stores |-> <<>>]
    /\ active = {A, "b"}
    /\ cloned = FALSE
    /\ cnt = [drop |-> 0, recloss |-> 0, clone |-> 0, rot |-> 0, remove |-> 0, grant |-> 0, rid |-> 0, hostile |-> 0, rotOpen |-> FALSE]

\* What a node's filter holds: its admissible credentials for this connection.
Creds(s) == IF s.view = "departed" \/ s.ep = 0 THEN {} ELSE {s.ep}
Min(a, b) == IF a < b THEN a ELSE b
\* acked_pos: nothing below it is pending. It moves only with no Offer unanswered, to what
\* is both acknowledged and tested.
Advance(s) == IF ~AckTested THEN [s EXCEPT !.rec.acked = s.rec.ackRecv]
              ELSE IF s.rec.outst THEN s
              ELSE [s EXCEPT !.rec.acked = LET v == Min(s.rec.ackRecv, s.rec.tested)
                                           IN IF v > @ THEN v ELSE @]
Pending(s) == {c \in Creds(s) : s.changed[c] > s.rec.acked}
TestSet(s) == IF TestPending THEN Pending(s) ELSE {c \in Creds(s) : s.changed[c] > s.rec.ranPos}

\* The test a change or arrival runs: on the pending set against the stored filter.
Hits(s, stored) == IF s.rec.open THEN {} ELSE TestSet(s) \cap stored
Whole(s) == [t |-> "B", gen |-> s.rec.sentGen + 1, base |-> 0, adds |-> Creds(s), pos |-> s.pos]
Additions(s) ==
    [t |-> "B", gen |-> s.rec.sentGen + 1, base |-> s.rec.ackedGen,
     adds |-> {c \in Creds(s) : s.changed[c] > s.rec.acked}, pos |-> s.pos]
Sent(s, b) == [s EXCEPT !.rec.sentGen = b.gen, !.rec.sentPos = b.pos]
\* A test starts on what is stored now; tested_pos moves when it has no Offer unanswered.
RunTest(s) ==
    LET hits == Hits(s, s.rec.stored)
    IN Advance([s EXCEPT !.rec.ranPos = s.pos, !.rec.ranGen = s.rec.gen, !.rec.outst = hits # {},
                         !.rec.tested = IF hits = {} THEN s.pos ELSE @])
HitMsg(s) == LET h == Hits(s, s.rec.stored) IN
    IF h # {} THEN <<[t |-> "Hit", c |-> CHOOSE x \in h : TRUE]>> ELSE <<>>
\* An Offer was answered: the test it came from is done, or another one is due.
Finish(s) == IF s.rec.ranPos = s.pos /\ s.rec.ranGen = s.rec.gen
             THEN Advance([s EXCEPT !.rec.tested = s.rec.ranPos, !.rec.outst = FALSE])
             ELSE RunTest(s)
FinishMsg(s) == IF s.rec.ranPos = s.pos /\ s.rec.ranGen = s.rec.gen THEN <<>> ELSE HitMsg(s)
Dig(s) == IF SReconcile THEN <<[t |-> "Dig", open |-> s.rec.open]>> ELSE <<>>
\* A connection's Pull carries the requester's cursor: the position of the peer's rotation it has applied.
PullCur(s) == IF CursorReport /\ s.rec.seen > 0 THEN <<[t |-> "Past", ep |-> s.rec.seen]>> ELSE <<>>
\* Pending again for this record alone: below this credential's changed_at, re-tested against
\* the stored filter. The peer's ack stands (it still holds the beacon), so no beacon is re-sent.
Repend(s) ==
    IF ~LostRetest \/ s.ep = 0 THEN s
    ELSE LET b == s.changed[s.ep] - 1
         IN [s EXCEPT !.rec.acked = Min(@, b), !.rec.tested = IF RepTested THEN Min(@, b) ELSE @, !.rec.ranPos = 0]
Close(s) == Repend([s EXCEPT !.rec.open = FALSE])
\* The open ends at this node's rotation: proved by a credential no longer current, not judged a holder.
Stale(s) == s.rec.proof = "cred" /\ s.rec.proofEp # s.ep /\ s.view # "holder"

Connect(x, y) ==
    LET same == st[x].rec.rid # 0 /\ st[x].rec.rid = st[y].rec.rid
        rid == cnt.rid + 1
        Fresh(s) == [s EXCEPT !.rec = [Rec0 EXCEPT !.rid = rid]]
        Start(s) == [s EXCEPT !.rec.digRead = ~SReconcile]
        sx == Start(IF same THEN st[x] ELSE Fresh(st[x]))
        sy == Start(IF same THEN st[y] ELSE Fresh(st[y]))
        Msg(s) == IF same /\ s.rec.ackedGen > 0 THEN Additions(s) ELSE Whole(s)
    IN
    /\ link = {}
    /\ x \in active /\ y \in active
    /\ x = A /\ y # A
    /\ link' = {x, y}
    /\ st' = [st EXCEPT ![x] = Sent(sx, Msg(sx)), ![y] = Sent(sy, Msg(sy))]
    /\ q' = [q EXCEPT ![y] = Dig(sx) \o <<Msg(sx)>> \o PullCur(sx), ![x] = Dig(sy) \o <<Msg(sy)>> \o PullCur(sy)]
    /\ cnt' = IF same THEN cnt ELSE [cnt EXCEPT !.rid = rid]
    /\ UNCHANGED <<role, removed, epoch, active, cloned>>

Drop ==
    /\ link # {}
    /\ cnt.drop < MaxDrop
    /\ link' = {}
    /\ q' = [s \in Stores |-> <<>>]
    /\ st' = [s \in Stores |-> [st[s] EXCEPT !.rec.outst = FALSE, !.rec.rejected = FALSE, !.rec.sentRot = 0, !.rec.past = 0, !.rec.digRead = FALSE,
                                                 !.rec.ackRecv = st[s].rec.acked, !.rec.tested = st[s].rec.acked,
                                                 !.rec.ranPos = 0, !.rec.ranGen = 0]]
    /\ cnt' = [cnt EXCEPT !.drop = @ + 1]
    /\ UNCHANGED <<role, removed, epoch, active, cloned>>

Loses(s) == s \notin link /\ s \in active /\ cnt.recloss < MaxRecLoss
LoseRecord(s) ==
    /\ Loses(s)
    /\ st' = [st EXCEPT ![s].rec = Rec0]
    /\ cnt' = [cnt EXCEPT !.recloss = @ + 1]
    /\ UNCHANGED <<role, removed, epoch, link, q, active, cloned>>

Clone ==
    /\ "c" \in Stores
    /\ cnt.clone < MaxClone
    /\ ~cloned
    /\ st' = [st EXCEPT !["c"] = st["b"]]
    /\ role' = [role EXCEPT !["c"] = role["b"]]
    /\ removed' = [removed EXCEPT !["c"] = removed["b"]]
    /\ cloned' = TRUE
    /\ cnt' = [cnt EXCEPT !.clone = @ + 1]
    /\ UNCHANGED <<epoch, link, q, active>>
Activate ==
    /\ cloned /\ "c" \notin active
    /\ active' = active \cup {"c"}
    /\ UNCHANGED <<st, role, removed, epoch, link, q, cloned, cnt>>

\* A credential change at n: pending from here on.
Touch(s, c) == [s EXCEPT !.pos = @ + 1, !.changed[c] = s.pos + 1]

\* Sends the additions a change makes; tested on the next Test.
SendAdd(n) ==
    LET s == st[n] b == Additions(s) IN
    /\ n \in link
    /\ \E c \in Creds(s) : s.changed[c] > s.rec.sentPos
    /\ s.rec.ackedGen > 0 \/ s.rec.sentGen > 0
    /\ st' = [st EXCEPT ![n] = Sent(@, b)]
    /\ q' = [q EXCEPT ![Other(n, link)] = Append(@, b)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvB(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "B"
    /\ IF m.base = 0 \/ m.base = s.rec.gen \/ ~GenBase
       THEN LET s2 == [s EXCEPT !.rec.stored = IF m.base = 0 THEN m.adds ELSE @ \cup m.adds, !.rec.gen = m.gen]
                testNow == TestAtArrival /\ ~s.rec.outst
            IN
            /\ st' = [st EXCEPT ![n] = IF testNow THEN RunTest(s2) ELSE s2]
            /\ q' = [q EXCEPT ![n] = Tail(@),
                               ![p] = (@ \o <<[t |-> "Ack", gen |-> m.gen, pos |-> m.pos]>>) \o (IF testNow THEN HitMsg(s2) ELSE <<>>)]
       ELSE /\ UNCHANGED st
            /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, [t |-> "Unk"])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvAck(n) ==
    LET m == Head(q[n]) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Ack"
    /\ st' = [st EXCEPT ![n] = Advance([@ EXCEPT !.rec.ackedGen = m.gen, !.rec.ackRecv = m.pos])]
    /\ q' = [q EXCEPT ![n] = Tail(@)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvUnk(n) ==
    LET m == Head(q[n]) p == Other(n, link) b == Whole(st[n]) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Unk"
    /\ st' = [st EXCEPT ![n] = Sent(@, b)]
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, b)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

Test(n) ==
    LET s == st[n] p == Other(n, link) IN
    /\ n \in link
    /\ ~s.rec.outst
    /\ s.rec.digRead \/ ~OfferGate
    /\ s.rec.ranPos # s.pos \/ s.rec.ranGen # s.rec.gen
    /\ st' = [st EXCEPT ![n] = RunTest(s)]
    /\ q' = [q EXCEPT ![p] = @ \o HitMsg(s)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvHit(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n] ok == m.c \in Creds(s) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Hit"
    /\ st' = IF ok THEN [st EXCEPT ![n].rec.open = TRUE, ![n].rec.proof = "cred", ![n].rec.proofEp = m.c]
             ELSE st
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, [t |-> "Reply", ok |-> ok, c |-> m.c, tag |-> ok])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvReply(n) ==
    LET m == Head(q[n]) s == st[n] p == Other(n, link)
        accepted == m.ok /\ (m.tag \/ ~TagCheck)
        ok == accepted /\ m.c \in Creds(s)
        s2 == [s EXCEPT !.rec.open = @ \/ ok, !.rec.proof = IF ok THEN "cred" ELSE @, !.rec.proofEp = IF ok THEN m.c ELSE @]
        decline == IF accepted /\ ~ok /\ ~s.rec.open /\ DeclineLost THEN <<[t |-> "Lost"]>> ELSE <<>> IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Reply"
    /\ st' = [st EXCEPT ![n] = Finish(s2)]
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = (@ \o decline) \o FinishMsg(s2)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* An adversary peer answers a Hit "accepted" for a credential it lacks.
HostileReply(n) ==
    LET p == Other(n, link) IN
    /\ Hostile
    /\ n \in link
    /\ q[n] # <<>> /\ Head(q[n]).t = "Hit"
    /\ q' = [q EXCEPT ![n] = Tail(@),
                      ![p] = Append(@, [t |-> "Reply", ok |-> TRUE, c |-> Head(q[n]).c, tag |-> FALSE])]
    /\ UNCHANGED <<st, role, removed, epoch, link, active, cloned, cnt>>

\* The adversary peer's filter claims every credential.
HostileFilter(n) ==
    LET p == Other(n, link) IN
    /\ Hostile
    /\ n \in link /\ n # A /\ cnt.hostile = 0
    /\ cnt' = [cnt EXCEPT !.hostile = 1]
    /\ q' = [q EXCEPT ![p] = Append(@, [t |-> "B", gen |-> st[n].rec.sentGen + 1, base |-> 0, adds |-> 1..MaxEp, pos |-> 0])]
    /\ st' = [st EXCEPT ![n] = Sent(@, [gen |-> st[n].rec.sentGen + 1, pos |-> st[n].rec.sentPos])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned>>

\* ByRole: the sender judges the peer a holder; the receiver's own judgment decides.
OfferRole(n) ==
    LET s == st[n] p == Other(n, link) IN
    /\ ByRoleOn
    /\ n \in link
    /\ s.rec.digRead \/ ~OfferGate
    /\ ~s.rec.open /\ ~s.rec.outst /\ s.view = "holder" /\ s.ep > 0
    /\ ~s.rec.rejected
    /\ st' = [st EXCEPT ![n].rec.outst = TRUE]
    /\ q' = [q EXCEPT ![p] = Append(@, [t |-> "Role", cs |-> Creds(s)])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvRole(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n]
        ok == s.ep > 0 /\ (s.view = "holder" \/ (m.cs \cap Creds(s) # {})) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Role"
    /\ st' = IF ok THEN [st EXCEPT ![n].rec.open = TRUE, ![n].rec.proof = "holder", ![n].rec.proofEp = s.ep]
             ELSE st
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = Append(@, [t |-> "RoleOk", ok |-> ok])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvRoleOk(n) ==
    LET m == Head(q[n]) s == st[n] p == Other(n, link)
        s2 == [s EXCEPT !.rec.open = @ \/ m.ok, !.rec.proof = IF m.ok THEN "holder" ELSE @,
                        !.rec.proofEp = IF m.ok THEN s.ep ELSE @, !.rec.rejected = ~m.ok] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "RoleOk"
    /\ st' = [st EXCEPT ![n] = Finish(s2)]
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = @ \o FinishMsg(s2)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* The event that ends sharing: the open is judged again on what n holds. After a
\* rotation Lost waits until the peer's Pull cursor has passed the rotation (`until`).
Judge(n) ==
    LET s == st[n] p == Other(n, link)
        gone == s.view = "departed"
        stale == Stale(s)
    IN
    /\ n \in link
    /\ s.rec.open
    /\ gone \/ stale
    /\ gone \/ ~Until \/ s.rec.past >= s.ep
    /\ st' = [st EXCEPT ![n] = Close(@)]
    /\ q' = [q EXCEPT ![p] = Append(@, [t |-> "Lost"])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvLost(n) ==
    LET m == Head(q[n]) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Lost"
    /\ st' = [st EXCEPT ![n] = Close(@)]
    /\ q' = [q EXCEPT ![n] = Tail(@)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* The digest: first in each direction. On a difference this side's list goes out as the peer's
\* digest is read, so it precedes every Offer this side sends (OfferGate).
RecvDig(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Dig"
    /\ st' = [st EXCEPT ![n].rec.digRead = TRUE]
    /\ q' = [q EXCEPT ![n] = Tail(@),
                      ![p] = IF m.open = s.rec.open THEN @ ELSE Append(@, [t |-> "List", open |-> s.rec.open])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* The peer's member list: a member only one side holds is closed and pending, on both sides.
RecvList(n) ==
    LET m == Head(q[n]) s == st[n] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "List"
    /\ st' = IF m.open = s.rec.open THEN st ELSE [st EXCEPT ![n] = Close(@)]
    /\ q' = [q EXCEPT ![n] = Tail(@)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

\* Rotation at a holder: the next epoch; a peer with L open gets the event.
Rotate(n) ==
    /\ n \in active
    /\ cnt.rot < MaxRot /\ epoch < MaxEp
    /\ role[n] /\ st[n].ep = epoch
    /\ epoch' = epoch + 1
    /\ st' = [st EXCEPT ![n] = Touch([@ EXCEPT !.ep = epoch + 1], epoch + 1)]
    /\ cnt' = [cnt EXCEPT !.rot = @ + 1, !.rotOpen = @ \/ (n \in link /\ \A s \in link : st[s].rec.open)]
    /\ UNCHANGED <<role, removed, link, q, active, cloned>>

\* The rotation event, in the stream of a member open at n (the `until` member). A
\* receiver with L open applies it unless removed. Past is its report of its position: a Pull's
\* cursor, or under Follow only after a Push marked `report`. Costs nothing when no `until` is set.
SendRot(n) ==
    LET s == st[n] p == Other(n, link) IN
    /\ n \in link
    /\ s.rec.open /\ s.ep > s.rec.sentRot /\ s.ep > st[p].rec.seen
    /\ st' = [st EXCEPT ![n].rec.sentRot = s.ep]
    /\ q' = [q EXCEPT ![p] = Append(@, [t |-> "Rot", ep |-> s.ep, rep |-> PushReport /\ Stale(s)])]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvRot(n) ==
    LET m == Head(q[n]) p == Other(n, link) s == st[n] IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Rot"
    /\ st' = IF s.rec.open /\ s.ep > 0 /\ s.ep < m.ep /\ ~removed[n]
             THEN [st EXCEPT ![n] = [Touch([@ EXCEPT !.ep = m.ep], m.ep) EXCEPT !.rec.seen = m.ep]]
             ELSE [st EXCEPT ![n].rec.seen = IF m.ep > @ THEN m.ep ELSE @]
    /\ q' = [q EXCEPT ![n] = Tail(@), ![p] = IF ~Follow \/ m.rep THEN Append(@, [t |-> "Past", ep |-> m.ep]) ELSE @]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

RecvPast(n) ==
    LET m == Head(q[n]) IN
    /\ n \in link
    /\ q[n] # <<>> /\ m.t = "Past"
    /\ st' = [st EXCEPT ![n].rec.past = IF m.ep > @ THEN m.ep ELSE @]
    /\ q' = [q EXCEPT ![n] = Tail(@)]
    /\ UNCHANGED <<role, removed, epoch, link, active, cloned, cnt>>

Grant(n) ==
    /\ n \in active
    /\ cnt.grant < MaxGrant
    /\ ~role[n]
    /\ role' = [role EXCEPT ![n] = TRUE]
    /\ removed' = [removed EXCEPT ![n] = FALSE]
    /\ st' = [st EXCEPT ![n] = Touch([@ EXCEPT !.ep = epoch], epoch)]
    /\ cnt' = [cnt EXCEPT !.grant = @ + 1]
    /\ UNCHANGED <<epoch, link, q, active, cloned>>

\* A removal of n's actor from L's role. The peer learns it by LearnView.
Remove(n) ==
    /\ n \in active
    /\ cnt.remove < MaxRemove
    /\ role[n]
    /\ role' = [role EXCEPT ![n] = FALSE]
    /\ removed' = [removed EXCEPT ![n] = TRUE]
    /\ cnt' = [cnt EXCEPT !.remove = @ + 1]
    /\ UNCHANGED <<st, epoch, link, q, active, cloned>>

\* A node's view of its peer's actor, learned at any time from group data.
LearnView(n, p) ==
    LET v == IF removed[p] THEN "departed" ELSE IF role[p] THEN "holder" ELSE "unknown" IN
    /\ n \in active /\ p \in active /\ n # p
    /\ {n, p} \subseteq {A, "b"} \/ {n, p} \subseteq {A, "c"}
    /\ st[n].view # v
    /\ st' = [st EXCEPT ![n].view = v, ![n].rec.rejected = FALSE]
    /\ UNCHANGED <<role, removed, epoch, link, q, active, cloned, cnt>>

Honest ==
    \/ \E n \in Stores :
        \/ SendAdd(n) \/ RecvB(n) \/ RecvAck(n) \/ RecvUnk(n) \/ Test(n) \/ RecvHit(n) \/ RecvReply(n)
        \/ OfferRole(n) \/ RecvRole(n) \/ RecvRoleOk(n) \/ Judge(n) \/ RecvLost(n)
        \/ SendRot(n) \/ RecvRot(n) \/ RecvPast(n) \/ RecvDig(n) \/ RecvList(n)
    \/ \E n, p \in Stores : LearnView(n, p)
    \/ \E y \in Stores : Connect(A, y)
    \/ Activate

Next ==
    \/ Honest
    \/ \E n \in Stores : Rotate(n) \/ Grant(n) \/ Remove(n) \/ LoseRecord(n) \/ HostileReply(n) \/ HostileFilter(n)
    \/ Clone
    \/ Drop

Spec == Init /\ [][Next]_vars /\ WF_vars(Honest)

\* Properties, in what the pair of nodes can observe. ------------------------
\* The rule on what each holds: judged from each node's view and credentials.
RuleAt(n, p) ==
    /\ st[n].ep > 0
    /\ st[n].view # "departed"
    /\ st[n].view = "holder" \/ st[n].ep = st[p].ep
\* Shared requires both sides' rules (each judges independently).
Rule(n, p) == RuleAt(n, p) /\ RuleAt(p, n)

Quiet ==
    /\ link # {}
    /\ \A n \in link :
        LET p == Other(n, link) s == st[n] IN
        /\ q[n] = <<>>
        /\ ~s.rec.outst
        /\ ~ENABLED Judge(n)
        /\ ~ENABLED Test(n)
        /\ ~ENABLED OfferRole(n)
        /\ ~ENABLED SendAdd(n)
        /\ ~ENABLED SendRot(n)
        /\ \A v \in {"departed","holder"} : ~ENABLED LearnView(n, p)

\* (1, 3) Once quiet, the pair share L exactly when the rule says so.
RuleHolds ==
    Quiet =>
      \A n \in link : LET p == Other(n, link) IN
        st[n].rec.open <=> (Rule(n, p) /\ (st[n].view # "unknown" \/ st[p].view # "unknown" \/ st[n].ep = st[p].ep))

\* (3) An open ended by a rotation does not stand: once quiet, no open rests on a stale proof, so the
\* requester's report of passing `until` always arrives.
UntilEnds == Quiet => \A n \in link : ~(st[n].rec.open /\ Stale(st[n]))

\* (3) A holder that was served at a rotation (L open on both sides then, no record lost)
\* reaches the new epoch. A one-sided open may leave a holder stranded, as the design accepts.
EpochReached == Quiet /\ cnt.rotOpen /\ cnt.recloss = 0 => \A n \in link : ~removed[n] /\ st[n].ep > 0 => st[n].ep = epoch
\* A drop only after the rotation: and at most 3 messages queued each way: the state bound of the drop cfgs.
DropAfterRot == (cnt.drop = 0 \/ cnt.rot = MaxRot) /\ \A s \in Stores : Len(q[s]) <= 3
Settled == Quiet
Settles == <>[]Settled
====
